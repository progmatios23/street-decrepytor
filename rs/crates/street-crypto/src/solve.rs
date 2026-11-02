//! Auto-solve on disk: only promote when header/magic validates beyond the key.

use crate::detect::CryptoRanking;
use crate::stub::{decrypt_region, extract_dw_ops, DwOp, StubLayout};
use crate::xor::{decrypt_blob, xor_repeat, DecryptHit};
use serde::{Deserialize, Serialize};
use street_core::entropy::{islands, shannon};
use street_core::pe::{executable_ranges, parse_pe, rva_to_off};
use street_core::transform::{image_transform, TransformKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolvedHit {
    pub kind: String,
    pub cipher: String,
    pub key_hex: String,
    pub magic: String,
    pub score: i32,
    pub offset: u64,
    pub size: usize,
    pub preview_hex: String,
    pub decrypted: bool,
    pub note: String,
    #[serde(skip)]
    pub plain: Option<Vec<u8>>,
}

pub fn auto_solve(data: &[u8], ranking: &CryptoRanking) -> Vec<SolvedHit> {
    let mut out = Vec::new();

    // 1) High-entropy islands → XOR / magic-anchored decrypt
    for isl in islands(data, 4096, 2048).into_iter().take(24) {
        let start = isl.offset as usize;
        let end = (start + isl.size as usize).min(data.len());
        if end <= start {
            continue;
        }
        let blob = &data[start..end];
        if let Some(h) = decrypt_blob_strict(blob) {
            out.push(SolvedHit {
                kind: "cipher".into(),
                cipher: h.cipher,
                key_hex: h.key_hex,
                magic: h.magic,
                score: h.score,
                offset: isl.offset,
                size: blob.len(),
                preview_hex: hex_preview(blob, 32),
                decrypted: true,
                note: format!("island H={:.2}", isl.h),
                plain: None,
            });
        }
    }

    // 2) Overlay / tail sample
    if data.len() > 0x10000 {
        let tail = &data[data.len().saturating_sub(0x10000)..];
        if let Some(h) = decrypt_blob_strict(tail) {
            out.push(SolvedHit {
                kind: "cipher".into(),
                cipher: h.cipher,
                key_hex: h.key_hex,
                magic: h.magic,
                score: h.score,
                offset: (data.len() - tail.len()) as u64,
                size: tail.len(),
                preview_hex: hex_preview(tail, 32),
                decrypted: true,
                note: "file_tail".into(),
                plain: None,
            });
        }
    }

    // 3) Dw-stub offline (Cs2-External class) — auto-locate
    if ranking.hits.iter().any(|h| h.system == "dw_stub") {
        if let Some(hit) = try_dw_stub_auto(data) {
            out.push(hit);
        }
    }

    // 4) Rolling XOR printable prefilter on last 32KB — report only high score + entropy drop
    let tail_off = data.len().saturating_sub(0x8000);
    let tail = &data[tail_off..];
    let h0 = shannon(tail);
    for mut r in rolling_xor_ascii(tail) {
        if let Some(ref plain) = r.plain {
            let h1 = shannon(&plain[..plain.len().min(4096)]);
            if h0 - h1 < 0.4 {
                continue; // no real decrypt — just printable noise
            }
        }
        r.offset = tail_off as u64;
        out.push(r);
    }

    // 5) zlib inflate islands
    for isl in islands(data, 4096, 2048).into_iter().take(16) {
        let start = isl.offset as usize;
        let end = (start + isl.size as usize).min(data.len());
        let blob = &data[start..end];
        if let Some(plain) = try_zlib(blob) {
            out.push(SolvedHit {
                kind: "cipher".into(),
                cipher: "zlib".into(),
                key_hex: String::new(),
                magic: "inflate".into(),
                score: 70,
                offset: isl.offset,
                size: plain.len(),
                preview_hex: hex_preview(&plain, 32),
                decrypted: true,
                note: format!("zlib inflate {} -> {}", blob.len(), plain.len()),
                plain: Some(plain),
            });
        }
    }

    out.sort_by(|a, b| b.score.cmp(&a.score));
    out
}

fn decrypt_blob_strict(blob: &[u8]) -> Option<DecryptHit> {
    let h = decrypt_blob(blob)?;
    // re-validate with stricter PE check
    let key = hex_to_bytes(&h.key_hex)?;
    let pt = xor_repeat(blob, &key);
    if h.magic == "pe" && !pe_ok(&pt) {
        return None;
    }
    if h.magic == "png" && (pt.len() < 16 || &pt[12..16] != b"IHDR") {
        return None;
    }
    Some(h)
}

fn pe_ok(blob: &[u8]) -> bool {
    if blob.len() < 0x40 || &blob[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes(blob[0x3C..0x40].try_into().unwrap()) as usize;
    e >= 0x40 && e + 4 <= blob.len().min(0x1000) && &blob[e..e + 4] == b"PE\0\0"
}

fn try_dw_stub_auto(data: &[u8]) -> Option<SolvedHit> {
    // The stub is a local cluster of code. Use the same windowed, executable-scoped
    // detector as the ranking so detect and solve cannot disagree.
    let ranges = executable_ranges(data);
    if ranges.is_empty() {
        return None;
    }
    let (cluster_off, dens) = crate::detect::densest_dw_window(data)?;
    let img = parse_pe(data).ok()?;
    // LEA rcx,[rip+disp32] = 48 8D 0D — search inside the same executable section.
    let (rs, re) = ranges
        .iter()
        .copied()
        .find(|(s, e)| cluster_off >= *s && cluster_off < *e)?;
    let mut stub_off = cluster_off;
    let search0 = cluster_off.saturating_sub(0x200).max(rs);
    let search1 = (cluster_off + 0x2800).min(re).min(data.len().saturating_sub(7));
    for i in search0..search1 {
        if data[i] == 0x48 && data[i + 1] == 0x8D && data[i + 2] == 0x0D {
            // require a push-ish byte shortly before (prolog) OR dw-ops shortly after
            let before = &data[i.saturating_sub(0x40)..i];
            let after = &data[i..data.len().min(i + 0x80)];
            let has_push = before.iter().any(|&b| (0x50..=0x57).contains(&b));
            let has_dw = (0..after.len().saturating_sub(1))
                .any(|k| crate::detect::dw_op_len(&after[k..]).is_some());
            if has_push || has_dw {
                stub_off = i;
                break;
            }
        }
    }
    let stub_rva = file_to_rva(&img, data, stub_off).unwrap_or(stub_off as u32) as u64;
    let ops = extract_dw_ops(&data[stub_off..data.len().min(stub_off + 0x3000)], stub_rva);
    if ops.len() < 16 {
        return Some(SolvedHit {
            kind: "trace_only".into(),
            cipher: "dw_stub".into(),
            key_hex: String::new(),
            magic: "none".into(),
            score: 30,
            offset: stub_off as u64,
            size: 0,
            preview_hex: String::new(),
            decrypted: false,
            note: format!(
                "stub cluster {cluster_off:#x} dens={dens} stub_off={stub_off:#x} but only {} dw-ops decoded",
                ops.len()
            ),
            plain: None,
        });
    }
    let Some(layout) = infer_layout(data, stub_off, stub_rva, ops) else {
        return Some(SolvedHit {
            kind: "trace_only".into(),
            cipher: "dw_stub".into(),
            key_hex: String::new(),
            magic: "none".into(),
            score: 35,
            offset: stub_off as u64,
            size: 0,
            preview_hex: hex_preview(&data[stub_off..data.len().min(stub_off + 16)], 16),
            decrypted: false,
            note: format!(
                "ops ok at {stub_off:#x} dens={dens} — missing lea→key region or loop total (need cmp rdi)"
            ),
            plain: None,
        });
    };
    let plain = decrypt_region(data, &layout);
    let plain_h = shannon(&plain[..plain.len().min(4096)]);
    let src_start = layout.key_region_file_off;
    let src_end = (src_start + layout.total_size).min(data.len());
    let src_h = if src_end > src_start {
        shannon(&data[src_start..src_end])
    } else {
        0.0
    };
    let entropy_drop = src_h - plain_h;

    let (magic, score, validated) = classify_dw_output(&plain, layout.total_size, entropy_drop, plain_h);
    let note = if validated {
        format!(
            "auto stub_off={stub_off:#x} dens={dens} ops={} block={:#x} total={:#x} magic={magic} H {src_h:.2}→{plain_h:.2}",
            layout.ops.len(),
            layout.block_size,
            layout.total_size
        )
    } else {
        let probe = probe_residual(&plain);
        format!(
            "transform applied at stub_off={stub_off:#x} dens={dens} ops={} but header unvalidated \
             (no PE/ZIP magic; H {src_h:.2}→{plain_h:.2}, drop {entropy_drop:.2} < 1.0) — not a decrypt. \
             residual: H {:.2}, {} printable runs / {} B, header {:?}, magics {:?}, sections {:?} — {}",
            layout.ops.len(),
            probe.entropy,
            probe.printable_runs,
            probe.printable_bytes,
            probe.header_dwords,
            probe.magics,
            probe.section_names,
            probe.hint
        )
    };
    Some(SolvedHit {
        kind: if validated { "cipher" } else { "trace_only" }.into(),
        cipher: "dw_stub".into(),
        key_hex: format!("{}ops", layout.ops.len()),
        magic: magic.into(),
        score,
        offset: layout.key_region_file_off as u64,
        size: plain.len(),
        preview_hex: hex_preview(&plain, 48),
        decrypted: validated,
        note,
        plain: Some(plain),
    })
}

/// Decide whether a dw-stub transform output is a *validated* decrypt.
///
/// `CRITICAL.md`: `decrypted=true` requires proof beyond the key. A recognized
/// magic (PE/ZIP) is proof. The Cs2-class container schema counts only with three
/// structural dwords **and** a real entropy drop — two coincidental dwords are not
/// a decrypt, which is exactly how the onx_cmd.exe `.reloc` blob was promoted.
///
/// Returns `(magic, score, validated)`.
pub(crate) fn classify_dw_output(
    plain: &[u8],
    total_size: usize,
    entropy_drop: f64,
    plain_h: f64,
) -> (&'static str, i32, bool) {
    let is_pe = pe_ok(plain);
    let is_zip = plain.starts_with(b"PK");
    let container = plain.len() >= 28 && {
        let d0 = u32::from_le_bytes(plain[0..4].try_into().unwrap());
        let d1 = u32::from_le_bytes(plain[4..8].try_into().unwrap());
        let d6 = u32::from_le_bytes(plain[24..28].try_into().unwrap());
        (0x1000..0x10_0000).contains(&d0)
            && (0x1000..0x10_0000).contains(&d1)
            && d6 == total_size as u32
            && entropy_drop >= 1.0
    };
    let magic = if is_pe {
        "pe"
    } else if is_zip {
        "zip"
    } else if container {
        "region"
    } else {
        "none"
    };
    let validated = magic != "none";
    let score = if is_pe || is_zip {
        95
    } else if container {
        90
    } else if plain_h < 6.0 {
        45
    } else {
        30
    };
    (magic, score, validated)
}

/// Characterise a transform output that failed validation.
///
/// A `decrypted=false` verdict is honest but, on its own, a dead end — it tells the
/// analyst the key was wrong without saying what the transform *did* recover. This
/// probe reports the residual structure so the next step is visible.
///
/// On `onx_cmd.exe` the dw-stub output recovers a 7-dword container header and
/// ~1.6 KB of printable fragments (PE section names such as `.idata$5` / `.00cfg`,
/// byte-drifted) while the body stays at H 7.38 across 560 blocks. That pattern —
/// a clean header, scattered readable metadata, high-entropy remainder — is a
/// second-layer signal, and this is what records it instead of dropping it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResidualProbe {
    pub entropy: f64,
    pub printable_runs: usize,
    pub printable_bytes: usize,
    pub longest_run_off: u64,
    pub longest_run: String,
    pub header_dwords: Vec<String>,
    pub zero_fraction: f64,
    /// Recognised magics in the output (`pe@0x…`, `png@0x…`). A magic in a
    /// non-validated transform is the strongest evidence the transform worked.
    pub magics: Vec<String>,
    /// PE-style section names in the output. `.text` / `.idata$5` / `.00cfg`
    /// only appear in a real MSVC image, so their presence says "the plaintext is
    /// (or contains) a PE" even when no `MZ`/`PE` header survived.
    pub section_names: Vec<String>,
    pub hint: String,
}

pub fn probe_residual(plain: &[u8]) -> ResidualProbe {
    let entropy = shannon(&plain[..plain.len().min(0x10000)]);
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < plain.len() {
        if plain[i].is_ascii_graphic() || plain[i] == b' ' {
            let s = i;
            while i < plain.len() && (plain[i].is_ascii_graphic() || plain[i] == b' ') {
                i += 1;
            }
            if i - s >= 12 {
                runs.push((s, i));
            }
        } else {
            i += 1;
        }
    }
    let printable_bytes: usize = runs.iter().map(|(a, b)| b - a).sum();
    let (loff, lrun) = runs
        .iter()
        .max_by_key(|(a, b)| b - a)
        .map(|(a, b)| {
            (
                *a,
                String::from_utf8_lossy(&plain[*a..(*b).min(*a + 64)]).into_owned(),
            )
        })
        .unwrap_or((0, String::new()));
    let header_dwords = (0..7)
        .filter(|k| (k + 1) * 4 <= plain.len())
        .map(|k| {
            format!(
                "0x{:08X}",
                u32::from_le_bytes(plain[k * 4..k * 4 + 4].try_into().unwrap())
            )
        })
        .collect();
    let zero_fraction = if plain.is_empty() {
        0.0
    } else {
        plain.iter().filter(|&&b| b == 0).count() as f64 / plain.len() as f64
    };

    // Magics: a PE/ZIP/PNG header surviving a transform that failed validation is
    // the strongest possible evidence that the transform is nonetheless correct.
    const MAGICS: &[(&[u8], &str)] = &[
        (b"PE\0\0", "pe"),
        (b"PK\x03\x04", "zip"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\x1f\x8b\x08", "gzip"),
        (b"\x7fELF", "elf"),
        (b"SQLite format 3", "sqlite"),
        (b"MSCF", "cab"),
    ];
    let mut magics: Vec<String> = Vec::new();
    for (m, name) in MAGICS {
        if m.len() <= plain.len() {
            if let Some(off) = plain.windows(m.len()).position(|w| w == *m) {
                magics.push(format!("{name}@{off:#x}"));
            }
        }
    }

    // PE section names. Curated prefixes only — an unconstrained 8-byte scan
    // matches random printable data and buries the real signal.
    const SEC_PREFIXES: &[&str] = &[
        ".text", ".rdata", ".data", ".bss", ".idata", ".edata", ".rsrc", ".reloc",
        ".pdata", ".debug", ".gfids", ".00cfg", ".CRT$", ".tls", ".didat", ".xdata",
        ".fptable", ".sdata", ".rodata",
    ];
    let mut section_names: Vec<String> = Vec::new();
    for p in SEC_PREFIXES {
        let pb = p.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = plain[from..].windows(pb.len()).position(|w| w == pb) {
            let at = from + rel;
            let mut end = at + pb.len();
            while end < plain.len()
                && (plain[end].is_ascii_alphanumeric() || plain[end] == b'_' || plain[end] == b'$')
            {
                end += 1;
            }
            let name = String::from_utf8_lossy(&plain[at..end]).into_owned();
            if !section_names.contains(&name) {
                section_names.push(name);
            }
            from = at + 1;
            if from >= plain.len() {
                break;
            }
        }
    }
    section_names.truncate(16);

    let hint = if entropy > 7.0 && printable_bytes < plain.len() / 100 {
        "output stays high-entropy with <1% printable — body carries a second layer the stub does not touch"
            .to_string()
    } else if !section_names.is_empty() || !magics.is_empty() {
        "output contains PE section names / known magics — the transform recovered real structure; inspect the header and the named regions"
            .to_string()
    } else if entropy > 6.5 {
        "output is mixed: printable islands exist but the body is not plaintext".to_string()
    } else {
        "output entropy dropped — inspect the header and the printable islands".to_string()
    };
    ResidualProbe {
        entropy,
        printable_runs: runs.len(),
        printable_bytes,
        longest_run_off: loff as u64,
        longest_run: lrun,
        header_dwords,
        zero_fraction,
        magics,
        section_names,
        hint,
    }
}

fn infer_layout(data: &[u8], stub_off: usize, stub_rva: u64, ops: Vec<DwOp>) -> Option<StubLayout> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let stub = &data[stub_off..data.len().min(stub_off + 0x3000)];
    let mut layout = StubLayout {
        stub_file_off: stub_off,
        ops,
        key_region_file_off: 0,
        block_size: 0x400,
        total_size: 0,
    };
    let mut decoder = Decoder::with_ip(64, stub, stub_rva, DecoderOptions::NONE);
    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            break;
        }
        if insn.mnemonic() == Mnemonic::Lea
            && insn.op0_kind() == OpKind::Register
            && insn.op0_register() == Register::RCX
            && (insn.memory_base() == Register::RIP || insn.is_ip_rel_memory_operand())
        {
            let target = if insn.is_ip_rel_memory_operand() {
                insn.ip_rel_memory_address()
            } else {
                let disp = insn.memory_displacement64() as i64;
                (insn.ip() as i64)
                    .wrapping_add(insn.len() as i64)
                    .wrapping_add(disp) as u64
            };
            if let Ok(img) = parse_pe(data) {
                // Decoder IPs are RVAs (we seed with section RVA), not VAs
                let rva = if target >= img.image_base {
                    (target - img.image_base) as u32
                } else {
                    target as u32
                };
                if let Some(off) = rva_to_off(&img, rva) {
                    layout.key_region_file_off = off as usize;
                }
            }
        }
        if insn.mnemonic() == Mnemonic::Add
            && insn.op0_register() == Register::RDI
            && matches!(
                insn.op1_kind(),
                OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64
            )
        {
            let v = match insn.op1_kind() {
                OpKind::Immediate8to64 => insn.immediate8to64() as u32,
                OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32(),
                _ => 0,
            };
            if v >= 0x40 && v <= 0x4000 {
                layout.block_size = v as usize;
            }
        }
        if insn.mnemonic() == Mnemonic::Cmp && insn.op0_register() == Register::RDI {
            let v = match insn.op1_kind() {
                OpKind::Immediate8to64 => insn.immediate8to64() as u32,
                OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32(),
                OpKind::Immediate64 => insn.immediate64() as u32,
                _ => 0,
            };
            if v >= 0x1000 {
                layout.total_size = v as usize;
            }
        }
    }
    if layout.ops.is_empty() {
        return None;
    }
    if layout.key_region_file_off == 0 {
        return None;
    }
    if layout.block_size == 0 {
        layout.block_size = 0x400;
    }
    if layout.total_size == 0 {
        // fallback: remainder of containing section / capped
        layout.total_size = data
            .len()
            .saturating_sub(layout.key_region_file_off)
            .min(0x8_0000);
    }
    if layout.key_region_file_off + layout.total_size > data.len() {
        layout.total_size = data.len().saturating_sub(layout.key_region_file_off);
    }
    let _ = image_transform(TransformKind::Cipher, "dw_stub", None);
    Some(layout)
}

fn file_to_rva(img: &street_core::image::LoadedImage, _data: &[u8], file_off: usize) -> Option<u32> {
    for s in &img.sections {
        let start = s.raw_off as usize;
        let end = start + s.raw_size as usize;
        if file_off >= start && file_off < end {
            return Some(s.va + (file_off - start) as u32);
        }
    }
    None
}

fn rolling_xor_ascii(blob: &[u8]) -> Vec<SolvedHit> {
    let mut out = Vec::new();
    if blob.len() < 64 {
        return out;
    }
    // Do not XOR-bruteforce an already-valid PE image head.
    if pe_ok(blob) {
        return out;
    }
    for k in 1u8..=255 {
        let dec: Vec<u8> = blob.iter().map(|b| b ^ k).collect();
        let printable = dec
            .iter()
            .take(0x1000)
            .filter(|&&b| (32..127).contains(&b) || matches!(b, 9 | 10 | 13))
            .count();
        let denom = (dec.len().min(0x1000) as f64).max(1.0);
        let ratio = printable as f64 / denom;
        if ratio >= 0.85 {
            let h = shannon(&dec[..dec.len().min(4096)]);
            // key=0x09 on zero-heavy PE pads → tabs/sparse dots; need real text entropy
            if h < 5.5 {
                continue;
            }
            let uniq = {
                let mut u = [false; 256];
                for &b in dec.iter().take(4096) {
                    if (32..127).contains(&b) {
                        u[b as usize] = true;
                    }
                }
                u.iter().filter(|&&x| x).count()
            };
            if uniq < 40 {
                continue;
            }
            out.push(SolvedHit {
                kind: "cipher".into(),
                cipher: "xor1_printable".into(),
                key_hex: format!("{k:02x}"),
                magic: "ascii".into(),
                score: (ratio * 80.0) as i32,
                offset: 0,
                size: blob.len(),
                preview_hex: hex_preview(&dec, 32),
                decrypted: true,
                note: format!("printable_ratio={ratio:.2} H={h:.2}"),
                plain: Some(dec),
            });
            break;
        }
    }
    out
}

fn try_zlib(blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 2 {
        return None;
    }
    if blob[0] & 0x0F != 8 {
        return None;
    }
    if ((blob[0] as u16) << 8 | blob[1] as u16) % 31 != 0 {
        return None;
    }
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut d = ZlibDecoder::new(&blob[..blob.len().min(2 << 20)]);
    let mut out = Vec::new();
    if d.read_to_end(&mut out).is_ok() && out.len() >= 32 {
        Some(out)
    } else {
        None
    }
}

fn hex_preview(b: &[u8], n: usize) -> String {
    b.iter()
        .take(n)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The onx_cmd.exe regression: a `.reloc` blob whose decoded output happened
    /// to carry two plausible size dwords (d0 in range, d6 == total) but no magic
    /// and only a 0.5 entropy drop must NOT be reported as a decrypt.
    #[test]
    fn region_without_entropy_drop_is_not_decrypt() {
        let mut plain = vec![0u8; 64];
        plain[0..4].copy_from_slice(&0x0004_6110u32.to_le_bytes()); // plausible size
        plain[4..8].copy_from_slice(&0x0003_d362u32.to_le_bytes()); // plausible size
        plain[24..28].copy_from_slice(&0x0008_c000u32.to_le_bytes()); // == total
        let (magic, _score, ok) = classify_dw_output(&plain, 0x8c000, 0.545, 7.384);
        assert_eq!(magic, "none");
        assert!(!ok, "coincidental dwords + small entropy drop is not a decrypt");
    }

    /// A real Cs2-class container: three sane dwords, d6 == total, and the
    /// transform collapsed entropy by ≥1.0 bit/byte.
    #[test]
    fn region_with_entropy_drop_is_decrypt() {
        let mut plain = vec![0u8; 64];
        plain[0..4].copy_from_slice(&0x0001_2000u32.to_le_bytes());
        plain[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        plain[24..28].copy_from_slice(&0x0002_0000u32.to_le_bytes());
        let (magic, _score, ok) = classify_dw_output(&plain, 0x2_0000, 3.2, 4.8);
        assert_eq!(magic, "region");
        assert!(ok);
    }

    #[test]
    fn pe_magic_is_proof_without_entropy_gate() {
        let mut plain = vec![0u8; 0x80];
        plain[0..2].copy_from_slice(b"MZ");
        plain[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        plain[0x40..0x44].copy_from_slice(b"PE\0\0");
        let (magic, _score, ok) = classify_dw_output(&plain, 0x80, 0.1, 7.9);
        assert_eq!(magic, "pe");
        assert!(ok);
    }
}
