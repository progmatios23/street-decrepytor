//! Static crypto / protector *system* ranking from disk. Majority of evidence lives here.

use serde::{Deserialize, Serialize};
use street_core::entropy::{islands, printable_ratio, shannon};
use street_core::pe::{executable_ranges, parse_pe, section_bytes, text_section};
use street_core::{Confidence, Origin};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHit {
    pub system: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub offsets: Vec<u64>,
    pub origin: Origin,
    pub rank_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoRanking {
    pub schema_version: u32,
    pub primary: String,
    pub playbook: String,
    pub hits: Vec<CryptoHit>,
    pub notes: Vec<String>,
    pub entropy_global: f64,
    pub islands: usize,
}

pub fn detect_systems(data: &[u8]) -> CryptoRanking {
    let mut hits: Vec<CryptoHit> = Vec::new();
    let window = &data[..data.len().min(24 << 20)];

    if let Some(h) = score_aes_ni(window) {
        hits.push(h);
    }
    if let Some(h) = score_pxor(window) {
        hits.push(h);
    }
    if let Some(h) = score_xor_imm(window) {
        hits.push(h);
    }
    if let Some(h) = score_chacha(window) {
        hits.push(h);
    }
    if let Some(h) = score_tea(window) {
        hits.push(h);
    }
    if let Some(h) = score_named(
        window,
        &[b"Themida", b"WinLicense", b"Oreans Technologies", b"SecureEngine"],
        &[b"Oreans", b".themida"],
        "themida",
        0.55,
    ) {
        hits.push(h);
    }
    if let Some(h) = score_named(
        window,
        &[b"VMProtect", b"VMProtect begin", b"VMProtect end"],
        &[b".vmp0", b".vmp1"],
        "vmprotect",
        0.5,
    ) {
        hits.push(h);
    }
    if let Some(h) = score_named(window, &[b"UPX0", b"UPX1", b"UPX!"], &[], "upx", 0.7) {
        hits.push(h);
    }
    if let Some(h) = score_dotnet_crypto(window) {
        hits.push(h);
    }
    if let Some(h) = score_protector_sections(data) {
        hits.push(h);
    }
    if let Some(h) = score_empty_text(data) {
        hits.push(h);
    }
    if let Some(h) = score_dw_stub_density(window) {
        hits.push(h);
    }
    if let Some(h) = score_rc4_hint(window) {
        hits.push(h);
    }

    hits.sort_by(|a, b| {
        b.rank_score
            .partial_cmp(&a.rank_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let (primary, playbook) = pick_primary(&hits, data);
    let ent = shannon(&window[..window.len().min(1 << 16)]);
    let isl = islands(window, 4096, 2048);

    let mut notes = vec![
        "Static disk ranking only — no process spawn.".into(),
        "cipher transforms require auto-solve confirmation (magic/header beyond key).".into(),
        "Themida/VMP: playbook is live dump; static cannot lift the VM.".into(),
    ];
    if printable_ratio(window) < 0.2 {
        notes.push("low printable ratio — packed or encrypted payload likely".into());
    }

    CryptoRanking {
        schema_version: 1,
        primary,
        playbook,
        hits,
        notes,
        entropy_global: ent,
        islands: isl.len(),
    }
}

fn pick_primary(hits: &[CryptoHit], data: &[u8]) -> (String, String) {
    // Packed hosts: empty .text beats a weak/false dw_stub ranking
    if let Some(empty) = hits.iter().find(|h| h.system == "empty_text_runtime") {
        if empty.confidence >= 0.65 {
            return ("runtime_section_decryptor".into(), "live_dump_wait_text".into());
        }
    }
    // Named protector beats a false TEA / AES-NI / XOR constant ranking.
    for (name, play) in [
        ("themida", "themida_live_dump"),
        ("vmprotect", "vmp_live_dump"),
        ("upx", "upx_d"),
    ] {
        if let Some(h) = hits.iter().find(|h| h.system == name) {
            if h.confidence >= 0.5 {
                return (name.into(), play.into());
            }
        }
    }
    if let Some(h) = hits.first() {
        let play = match h.system.as_str() {
            "themida" | "empty_text_runtime" => "themida_live_dump",
            "vmprotect" => "vmp_live_dump",
            "upx" => "upx_d",
            "aes_ni" => "aes_ni_trace",
            "chacha20" => "chacha_recover",
            "tea_delta" => "tea_recover",
            "simd_xor_string" | "xor_imm_loop" => "xor_recover",
            "dw_stub" => "dw_stub_offline",
            "dotnet_crypto" => "dotnet_crypto_trace",
            "rc4_hint" => "rc4_recover",
            _ => "generic",
        };
        if h.system == "empty_text_runtime" {
            return ("runtime_section_decryptor".into(), "live_dump_wait_text".into());
        }
        return (h.system.clone(), play.into());
    }
    let _ = data;
    ("unknown".into(), "generic".into())
}

fn score_aes_ni(data: &[u8]) -> Option<CryptoHit> {
    let mut offs = Vec::new();
    // 66 0F 38 DC/DD/DE/DF  or 66 0F 3A DF
    let mut i = 0;
    while i + 4 < data.len() {
        if data[i] == 0x66 && data[i + 1] == 0x0F {
            if data[i + 2] == 0x38 && matches!(data[i + 3], 0xDC | 0xDD | 0xDE | 0xDF) {
                offs.push(i as u64);
            }
            if data[i + 2] == 0x3A && data[i + 3] == 0xDF {
                offs.push(i as u64);
            }
        }
        i += 1;
        if offs.len() >= 80 {
            break;
        }
    }
    if offs.is_empty() {
        return None;
    }
    let conf = (0.35 + 0.02 * offs.len() as f32).min(0.95);
    Some(CryptoHit {
        system: "aes_ni".into(),
        confidence: conf,
        evidence: vec![format!("AES-NI insn count={}", offs.len())],
        offsets: offs.clone(),
        origin: Origin::Decoder,
        rank_score: conf * 100.0 + offs.len() as f32,
    })
}

fn score_pxor(data: &[u8]) -> Option<CryptoHit> {
    let mut offs = Vec::new();
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == 0x66 && data[i + 1] == 0x0F && data[i + 2] == 0xEF {
            offs.push(i as u64);
            if offs.len() >= 80 {
                break;
            }
        }
        i += 1;
    }
    if offs.len() < 3 {
        return None;
    }
    let conf = (0.25 + 0.01 * offs.len() as f32).min(0.9);
    Some(CryptoHit {
        system: "simd_xor_string".into(),
        confidence: conf,
        evidence: vec![format!("pxor density={}", offs.len())],
        offsets: offs,
        origin: Origin::Decoder,
        rank_score: conf * 90.0,
    })
}

fn score_xor_imm(data: &[u8]) -> Option<CryptoHit> {
    let mut offs = Vec::new();
    let mut i = 0;
    while i + 10 < data.len() {
        if data[i] == 0x48 && data[i + 1] == 0xB8 {
            let window = &data[i..data.len().min(i + 48)];
            if window.iter().any(|&b| b == 0x30 || b == 0x31)
                || window.windows(2).any(|w| w == [0x80, 0x30])
            {
                offs.push(i as u64);
            }
            if offs.len() >= 40 {
                break;
            }
        }
        i += 1;
    }
    if offs.len() < 2 {
        return None;
    }
    let conf = (0.2 + 0.03 * offs.len() as f32).min(0.75);
    Some(CryptoHit {
        system: "xor_imm_loop".into(),
        confidence: conf,
        evidence: vec![format!("mov rax,imm64 + xor window hits={}", offs.len())],
        offsets: offs,
        origin: Origin::Heuristic,
        rank_score: conf * 70.0,
    })
}

fn score_chacha(data: &[u8]) -> Option<CryptoHit> {
    for mk in [b"expand 32-byte k".as_slice(), b"expand 16-byte k".as_slice()] {
        if let Some(i) = find_bounded(data, mk) {
            return Some(CryptoHit {
                system: "chacha20".into(),
                confidence: 0.92,
                evidence: vec![format!("constant {:?} @ {i:#x}", std::str::from_utf8(mk).unwrap_or("?"))],
                offsets: vec![i as u64],
                origin: Origin::Signature,
                rank_score: 95.0,
            });
        }
    }
    None
}

fn score_tea(data: &[u8]) -> Option<CryptoHit> {
    // 0x9E3779B9 LE
    let pat = [0xB9, 0x79, 0x37, 0x9E];
    let mut offs = Vec::new();
    for i in 0..data.len().saturating_sub(4) {
        if data[i..i + 4] == pat {
            offs.push(i as u64);
            if offs.len() >= 20 {
                break;
            }
        }
    }
    if offs.is_empty() {
        return None;
    }
    Some(CryptoHit {
        system: "tea_delta".into(),
        confidence: 0.7,
        evidence: vec![format!("TEA delta 0x9E3779B9 count={}", offs.len())],
        offsets: offs,
        origin: Origin::Signature,
        rank_score: 72.0,
    })
}

fn score_dotnet_crypto(data: &[u8]) -> Option<CryptoHit> {
    let marks = [
        b"System.Security.Cryptography".as_slice(),
        b"AesCryptoServiceProvider".as_slice(),
        b"Rijndael".as_slice(),
        b"ProtectedData".as_slice(),
    ];
    let mut evid = Vec::new();
    let mut offs = Vec::new();
    for mk in marks {
        if let Some(i) = find_bounded(data, mk) {
            evid.push(format!("{:?} @ {i:#x}", std::str::from_utf8(mk).unwrap_or("?")));
            offs.push(i as u64);
        }
    }
    if evid.is_empty() {
        return None;
    }
    Some(CryptoHit {
        system: "dotnet_crypto".into(),
        confidence: 0.8,
        evidence: evid,
        offsets: offs,
        origin: Origin::Signature,
        rank_score: 78.0,
    })
}

fn score_rc4_hint(data: &[u8]) -> Option<CryptoHit> {
    for mk in [b"RC4".as_slice(), b"arc4".as_slice(), b"Sbox".as_slice()] {
        if let Some(i) = find_bounded(data, mk) {
            return Some(CryptoHit {
                system: "rc4_hint".into(),
                confidence: 0.45,
                evidence: vec![format!("{:?} @ {i:#x}", std::str::from_utf8(mk).unwrap_or("?"))],
                offsets: vec![i as u64],
                origin: Origin::Heuristic,
                rank_score: 40.0,
            });
        }
    }
    None
}

fn score_protector_sections(data: &[u8]) -> Option<CryptoHit> {
    let img = parse_pe(data).ok()?;
    let names: Vec<String> = img
        .sections
        .iter()
        .map(|s| {
            s.name
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_ascii_lowercase()
        })
        .filter(|n| !n.is_empty())
        .collect();
    let themida = names.iter().any(|n| n.contains("themida") || n.contains("winlice"));
    let vmp = names.iter().any(|n| n.contains(".vmp") || n.contains("vmprotect"));
    if !themida && !vmp {
        return None;
    }
    let (system, play_note) = if themida {
        ("themida", "section name outranks TEA / dw_stub density")
    } else {
        ("vmprotect", "section name outranks opcode-density false leads")
    };
    Some(CryptoHit {
        system: system.into(),
        confidence: 0.92,
        evidence: vec![
            format!("section names: {}", names.join(", ")),
            play_note.into(),
        ],
        offsets: vec![],
        origin: Origin::Signature,
        rank_score: 140.0,
    })
}

fn score_empty_text(data: &[u8]) -> Option<CryptoHit> {
    let img = parse_pe(data).ok()?;
    let text = text_section(&img)?;
    if text.raw_size == 0 && text.vsize > 0x1000 {
        let virt = img.virtual_only_count();
        return Some(CryptoHit {
            system: "empty_text_runtime".into(),
            confidence: if virt >= 2 { 0.85 } else { 0.65 },
            evidence: vec![
                format!(".text SizeOfRawData=0 vsize={:#x}", text.vsize),
                format!("virtual_only_sections={virt}"),
            ],
            offsets: vec![text.va as u64],
            origin: Origin::Heuristic,
            rank_score: 88.0,
        });
    }
    let _ = section_bytes(data, text);
    None
}

/// Densest `0x2000`-byte window of Cs2-class `dword [rcx+disp]` arith encodings,
/// searched only inside executable sections. Returns `(window_file_offset, count)`.
///
/// Windowed, not a whole-file sum. The stub is a *local* cluster — a real one packs
/// ~200 matches into a single 8 KiB window — so the test is "is any window dense",
/// not "does the file contain many". A whole-file count is defeated by a large data
/// section: `onx_cmd.exe`'s `.reloc` is 1.3 MB **and marked RWX**, so an
/// executable-section filter alone still admits it, and it accumulated 205 chance
/// matches against `.text`'s 1. Per 8 KiB window that same blob yields single digits.
/// Length of a Cs2-class dword op at `b`, or `None` if the bytes are not one.
///
/// Matches `add|sub|xor dword [rcx+disp], imm32` (`81 /0,/5,/6`) and
/// `not dword [rcx+disp]` (`F7 /2`) across **every** displacement form:
/// mod=00 (no disp), mod=01 (disp8), mod=10 (disp32).
///
/// The previous matcher hard-coded `41|69|71|81` for the `0x81` opcode, i.e. only
/// mod=01 plus the mod=10 *add* form. A stub built from `81 A9`/`81 B1` (sub/xor
/// with a disp32 — the encoding MSVC emits once a block exceeds 0x7F bytes, which
/// a 0x400-byte block always does) was therefore invisible, and the `j += 7`
/// advance was wrong for the 6- and 10-byte forms.
#[inline]
pub(crate) fn dw_op_len(b: &[u8]) -> Option<usize> {
    if b.len() < 2 {
        return None;
    }
    let (op, modrm) = (b[0], b[1]);
    let mod_ = modrm >> 6;
    let reg = (modrm >> 3) & 7;
    if modrm & 7 != 1 || mod_ == 3 {
        return None; // must address [rcx+disp]; mod=3 is a register operand
    }
    let dlen = match mod_ {
        0 => 0,
        1 => 1,
        _ => 4,
    };
    if op == 0x81 && matches!(reg, 0 | 5 | 6) {
        return Some(2 + dlen + 4);
    }
    if op == 0xF7 && reg == 2 {
        return Some(2 + dlen);
    }
    None
}

pub(crate) fn densest_dw_window(data: &[u8]) -> Option<(usize, u32)> {
    const WIN: usize = 0x2000;
    const STEP: usize = 0x400;
    const MIN: u32 = 64;
    const SCAN_CAP: usize = 24 << 20;
    let ranges = executable_ranges(data);
    let scan: Vec<(usize, usize)> = if ranges.is_empty() {
        vec![(0, data.len())]
    } else {
        ranges
    };
    let mut best: Option<(usize, u32)> = None;
    let mut scanned = 0usize;
    for &(rs, re) in &scan {
        if re <= rs {
            continue;
        }
        let mut i = rs;
        while i < re {
            let end = re.min(i + WIN);
            let win = &data[i..end];
            let mut c = 0u32;
            let mut j = 0usize;
            while j < win.len() {
                match dw_op_len(&win[j..]) {
                    Some(n) if j + n <= win.len() => {
                        c += 1;
                        j += n;
                    }
                    _ => j += 1,
                }
            }
            if c >= MIN && best.map(|(_, bc)| c > bc).unwrap_or(true) {
                best = Some((i, c));
            }
            scanned += STEP;
            i += STEP;
        }
        if scanned >= SCAN_CAP {
            break;
        }
    }
    best
}

fn score_dw_stub_density(data: &[u8]) -> Option<CryptoHit> {
    // Cs2-External class: add/sub/xor/not dword [rcx+disp], imm. See
    // `densest_dw_window` for why this is windowed and executable-scoped.
    let (off, count) = densest_dw_window(data)?;
    let conf = (0.5 + (count as f32 / 400.0)).min(0.95);
    Some(CryptoHit {
        system: "dw_stub".into(),
        confidence: conf,
        evidence: vec![format!(
            "dword [rcx+disp] arith ops dens≈{count} in a {:#x}-byte window @ {off:#x} (Cs2-External-class stub)",
            0x2000usize
        )],
        offsets: vec![off as u64],
        origin: Origin::Decoder,
        rank_score: conf * 110.0,
    })
}

fn score_named(
    data: &[u8],
    strong: &[&[u8]],
    weak: &[&[u8]],
    name: &str,
    base: f32,
) -> Option<CryptoHit> {
    let mut found = Vec::new();
    let mut evid = Vec::new();
    let mut strong_hits = 0;
    for mk in strong {
        if let Some(i) = find_bounded(data, mk) {
            found.push(i as u64);
            evid.push(format!("strong {:?} @ {i:#x}", ascii(mk)));
            strong_hits += 1;
        }
    }
    let mut weak_hits = 0;
    for mk in weak {
        if let Some(i) = find_bounded(data, mk) {
            found.push(i as u64);
            evid.push(format!("weak {:?} @ {i:#x}", ascii(mk)));
            weak_hits += 1;
        }
    }
    if strong_hits == 0 && weak_hits < 2 {
        return None;
    }
    let mut conf = base + 0.12 * strong_hits as f32 + 0.04 * weak_hits as f32;
    if strong_hits == 0 {
        conf = conf.min(0.55);
    }
    conf = conf.min(0.98);
    Some(CryptoHit {
        system: name.into(),
        confidence: conf,
        evidence: evid,
        offsets: found,
        origin: Origin::Signature,
        rank_score: conf * 100.0 + strong_hits as f32 * 10.0,
    })
}

fn find_bounded(data: &[u8], mk: &[u8]) -> Option<usize> {
    let mut start = 0;
    while let Some(rel) = data[start..].windows(mk.len()).position(|w| w == mk) {
        let i = start + rel;
        let before = if i > 0 { data[i - 1] } else { 0 };
        let after = data.get(i + mk.len()).copied().unwrap_or(0);
        if !is_alnum(before) && !is_alnum(after) {
            return Some(i);
        }
        start = i + 1;
        if start >= data.len() {
            break;
        }
    }
    None
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn ascii(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[allow(dead_code)]
fn confidence_label(c: f32) -> Confidence {
    if c >= 0.75 {
        Confidence::High
    } else if c >= 0.45 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_upx_marker() {
        let mut blob = vec![0u8; 256];
        blob.extend_from_slice(b"\0UPX0\0");
        blob.extend_from_slice(b"\0UPX1\0");
        blob.extend_from_slice(&[0u8; 64]);
        let r = detect_systems(&blob);
        assert_eq!(r.primary, "upx");
        assert_eq!(r.playbook, "upx_d");
    }

    #[test]
    fn themida_outranks_tea_delta() {
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(&0x9E3779B9u32.to_le_bytes());
        blob.extend_from_slice(b"\0Themida\0");
        blob.extend_from_slice(&[0u8; 32]);
        let r = detect_systems(&blob);
        assert_eq!(r.primary, "themida");
        assert_eq!(r.playbook, "themida_live_dump");
    }

    #[test]
    fn themida_section_beats_dw_density() {
        let mut text = vec![0x90u8; 64];
        text.extend_from_slice(&0x9E3779B9u32.to_le_bytes());
        for _ in 0..128 {
            text.extend_from_slice(&[0x81, 0x41, 0x04, 0x22, 0x22, 0x22, 0x22]);
        }
        let mut pe = synth_pe_with_data_section(&text, &[0u8; 32]);
        // second section name sits 40 bytes after the first header
        let sh2 = 0x80 + 0x18 + 0xF0 + 40;
        pe[sh2..sh2 + 8].copy_from_slice(b".themida");
        let r = detect_systems(&pe);
        assert_eq!(r.primary, "themida", "{:?}", r.hits);
        assert_eq!(r.playbook, "themida_live_dump");
    }

    #[test]
    fn ranks_chacha_const() {
        let mut blob = b"\0\0\0\0".to_vec();
        blob.extend_from_slice(b"expand 32-byte k");
        blob.extend_from_slice(b"\0\0\0\0");
        let r = detect_systems(&blob);
        assert!(
            r.hits.iter().any(|h| h.system == "chacha20"),
            "{:?}",
            r.hits
        );
    }

    /// A non-executable data section full of `81 41` pairs must not rank dw_stub.
    /// This is the onx_cmd.exe regression: `.reloc` is 79% of the image and matched
    /// the 2-byte pattern 205 times against `.text`'s 1.
    #[test]
    fn dw_stub_ignores_non_executable_sections() {
        // .text: real code, one incidental match
        let mut text = vec![0x90u8; 4096];
        text[100..107].copy_from_slice(&[0x81, 0x41, 0x04, 0x11, 0x11, 0x11, 0x11]);
        // .reloc-like data: dense chance matches, NOT executable
        let mut reloc = Vec::new();
        for _ in 0..300 {
            reloc.extend_from_slice(&[0x81, 0x41, 0x04, 0x22, 0x22, 0x22, 0x22]);
        }
        let pe = synth_pe_with_data_section(&text, &reloc);
        let r = detect_systems(&pe);
        assert!(
            !r.hits.iter().any(|h| h.system == "dw_stub"),
            "dw_stub must not rank from a data section: {:?}",
            r.hits
        );

        // Sanity: the same bytes *in code* still rank.
        let mut code = vec![0x90u8; 64];
        for _ in 0..128 {
            code.extend_from_slice(&[0x81, 0x41, 0x04, 0x22, 0x22, 0x22, 0x22]);
        }
        let pe2 = synth_pe_with_data_section(&code, &[0u8; 16]);
        let r2 = detect_systems(&pe2);
        assert!(
            r2.hits.iter().any(|h| h.system == "dw_stub"),
            "dw_stub must still rank inside .text: {:?}",
            r2.hits
        );
    }

    /// Build a two-section PE32+ (`.text` exec, `.reloc` data) for the test above.
    fn synth_pe_with_data_section(text: &[u8], reloc: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let e = 0x80usize;
        b[e..e + 4].copy_from_slice(b"PE\0\0");
        b[e + 4..e + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        b[e + 6..e + 8].copy_from_slice(&2u16.to_le_bytes());
        b[e + 0x14..e + 0x16].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = e + 0x18;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        let sh = e + 0x18 + 0xF0;
        let text_off = 0x200usize;
        b[sh..sh + 8].copy_from_slice(b".text\0\0\0");
        b[sh + 8..sh + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        b[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh + 16..sh + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
        b[sh + 20..sh + 24].copy_from_slice(&(text_off as u32).to_le_bytes());
        b[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let reloc_off = text_off + text.len();
        let sh2 = sh + 40;
        b[sh2..sh2 + 8].copy_from_slice(b".reloc\0\0");
        b[sh2 + 8..sh2 + 12].copy_from_slice(&(reloc.len() as u32).to_le_bytes());
        b[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sh2 + 16..sh2 + 20].copy_from_slice(&(reloc.len() as u32).to_le_bytes());
        b[sh2 + 20..sh2 + 24].copy_from_slice(&(reloc_off as u32).to_le_bytes());
        b[sh2 + 36..sh2 + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());
        b.resize(reloc_off + reloc.len(), 0);
        b[text_off..text_off + text.len()].copy_from_slice(text);
        b[reloc_off..reloc_off + reloc.len()].copy_from_slice(reloc);
        b
    }
}
