//! Static crypto pipeline: rank → auto-solve → report. No process spawn.

use crate::carve::{carve_embedded_pe, carve_embedded_text, CarvedPe, CarvedText};
use crate::detect::{detect_systems, CryptoRanking};
use crate::protect::{scan_protect, ProtectSurface};
use crate::solve::{auto_solve, SolvedHit};
use crate::xor::DecryptHit;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use street_core::transform::{decrypted_flag, image_transform, Transform, TransformKind};
use street_core::{classify_bytes, sha256_bytes};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoReport {
    pub schema_version: u32,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub family: String,
    pub arch: String,
    pub ranking: CryptoRanking,
    #[serde(default)]
    pub protect: ProtectSurface,
    pub solved: Vec<SolvedHit>,
    pub carved: Vec<CarvedPe>,
    #[serde(default)]
    pub bundles: Vec<CarvedText>,
    pub image_transforms: Vec<Transform>,
    pub decrypted: bool,
    /// Structure recovered from a transform that did **not** validate. A
    /// `decrypted=false` verdict with no follow-up is a dead end; this records
    /// what the transform produced so the next step is visible.
    #[serde(default)]
    pub residual: Vec<ResidualFinding>,
    pub playbook_steps: Vec<String>,
    pub notes: Vec<String>,
}

/// A non-validated transform's residual structure, tagged with its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualFinding {
    pub cipher: String,
    pub offset: u64,
    pub probe: crate::solve::ResidualProbe,
}

pub fn run_static(path: &Path) -> Result<CryptoReport, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    run_static_bytes(path, &data)
}

pub fn run_static_bytes(path: &Path, data: &[u8]) -> Result<CryptoReport, String> {
    let profile = classify_bytes(data, Some(path)).map_err(|e| e.to_string())?;
    let ranking = detect_systems(data);
    let protect = scan_protect(data);
    let solved = auto_solve(data, &ranking);
    let carved_blobs = carve_embedded_pe(data, 16);
    let carved: Vec<CarvedPe> = carved_blobs.iter().map(|(c, _)| c.clone()).collect();
    // Embedded scripts/configs/personas — plaintext payload the host carries.
    let bundle_blobs = carve_embedded_text(data, 512, 64);
    let bundles: Vec<CarvedText> = bundle_blobs.iter().map(|(c, _)| c.clone()).collect();

    let mut transforms = Vec::new();
    for s in &solved {
        if s.decrypted && s.kind == "cipher" {
            transforms.push(image_transform(
                TransformKind::Cipher,
                &s.cipher,
                Some(&format!("off={:#x}", s.offset)),
            ));
        }
    }
    for c in &carved {
        transforms.push(image_transform(
            TransformKind::Copy,
            "embedded_pe",
            Some(&format!("off={:#x}", c.offset)),
        ));
    }

    let steps = playbook_steps(&ranking.playbook);
    let mut notes = ranking.notes.clone();
    notes.push(format!(
        "ranked {} systems; anti_debug={} tamper={} crypto_api={}; auto-solved {} hits; carved {} embedded PE, {} embedded text payloads; decrypted={}",
        ranking.hits.len(),
        protect.anti_debug.len(),
        protect.tamper.len(),
        protect.crypto_api.len(),
        solved.len(),
        carved.len(),
        bundles.len(),
        decrypted_flag(&transforms)
    ));
    if ranking.primary == "themida" || ranking.primary == "runtime_section_decryptor" {
        notes.push("Static cannot decrypt Themida VM — ranking flags live dump path.".into());
    }
    if !carved.is_empty() {
        notes.push("embedded MZ/PE carved — copies, not cipher unless a child also solves".into());
    }
    if !bundles.is_empty() {
        let kinds: Vec<String> = {
            let mut k: Vec<String> = bundles.iter().map(|b| b.kind.clone()).collect();
            k.sort();
            k.dedup();
            k
        };
        notes.push(format!(
            "embedded text payloads carved ({}): {} — plaintext the host ships, not a decrypt",
            bundles.len(),
            kinds.join(", ")
        ));
    }

    // A transform that ran but did not validate still has a story to tell.
    let mut residual: Vec<ResidualFinding> = Vec::new();
    for s in &solved {
        if !s.decrypted {
            if let Some(p) = &s.plain {
                residual.push(ResidualFinding {
                    cipher: s.cipher.clone(),
                    offset: s.offset,
                    probe: crate::solve::probe_residual(p),
                });
            }
        }
    }
    for r in &residual {
        notes.push(format!(
            "{} transform ran but did not validate: residual H {:.2}, {} printable runs / {} B, header {:?} — {}",
            r.cipher,
            r.probe.entropy,
            r.probe.printable_runs,
            r.probe.printable_bytes,
            r.probe.header_dwords,
            r.probe.hint
        ));
    }

    Ok(CryptoReport {
        schema_version: 1,
        path: path.display().to_string(),
        sha256: sha256_bytes(data),
        size: data.len() as u64,
        family: profile.family.as_str().into(),
        arch: profile.arch.as_str().into(),
        ranking,
        protect,
        solved,
        carved,
        bundles,
        image_transforms: transforms.clone(),
        decrypted: decrypted_flag(&transforms),
        residual,
        playbook_steps: steps,
        notes,
    })
}

pub fn write_report(report: &CryptoReport, out_dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let json_path = out_dir.join("CRYPTO_RANKING.json");
    std::fs::write(
        &json_path,
        serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let md = render_md(report);
    std::fs::write(out_dir.join("CRYPTO_RANKING.md"), md).map_err(|e| e.to_string())?;
    std::fs::write(
        out_dir.join("PROTECT_SURFACE.json"),
        serde_json::to_vec_pretty(&report.protect).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    // write solved payloads when small enough
    let hits = out_dir.join("hits");
    let _ = std::fs::create_dir_all(&hits);
    for (i, s) in report.solved.iter().enumerate().take(32) {
        let meta = serde_json::to_vec_pretty(s).unwrap_or_default();
        let _ = std::fs::write(hits.join(format!("{i:03}_{}.json", s.cipher)), meta);
        if let Some(ref plain) = s.plain {
            let ext = if plain.starts_with(b"MZ") {
                "exe"
            } else if plain.starts_with(b"PK") {
                "zip"
            } else {
                "bin"
            };
            let _ = std::fs::write(hits.join(format!("{i:03}_{}.{}", s.cipher, ext)), plain);
        }
    }
    // re-carve to write blobs (report only stores metadata)
    if let Ok(data) = std::fs::read(&report.path) {
        let carved_dir = out_dir.join("carved");
        let _ = std::fs::create_dir_all(&carved_dir);
        for (i, (meta, blob)) in carve_embedded_pe(&data, 16).into_iter().enumerate() {
            let _ = std::fs::write(
                carved_dir.join(format!("{i:03}_{:x}_{}.exe", meta.offset, &meta.sha256[..8])),
                &blob,
            );
            let _ = std::fs::write(
                carved_dir.join(format!("{i:03}_{:x}.json", meta.offset)),
                serde_json::to_vec_pretty(&meta).unwrap_or_default(),
            );
        }
        for (i, (meta, blob)) in carve_embedded_text(&data, 512, 64).into_iter().enumerate() {
            let ext = text_ext(&meta.kind);
            let _ = std::fs::write(
                carved_dir.join(format!("text_{i:03}_{:x}_{}.{ext}", meta.offset, meta.kind)),
                &blob,
            );
            let _ = std::fs::write(
                carved_dir.join(format!("text_{i:03}_{:x}.json", meta.offset)),
                serde_json::to_vec_pretty(&meta).unwrap_or_default(),
            );
        }
    }
    Ok(json_path)
}

fn text_ext(kind: &str) -> &'static str {
    match kind {
        "python" => "py",
        "batch" => "bat",
        "powershell" => "ps1",
        "json" => "json",
        "persona" | "prose" => "txt",
        _ => "txt",
    }
}

fn render_protect(s: &mut String, title: &str, hits: &[crate::protect::ProtectHit]) {
    s.push_str(&format!("### {title} ({})\n\n", hits.len()));
    if hits.is_empty() {
        s.push_str("_none on disk_\n\n");
        return;
    }
    for h in hits.iter().take(24) {
        match h.file_offset {
            Some(off) => s.push_str(&format!("- `{}` {} @ {:#x}\n", h.name, h.kind, off)),
            None => s.push_str(&format!("- `{}` {}\n", h.name, h.kind)),
        }
    }
    s.push('\n');
}

fn playbook_steps(playbook: &str) -> Vec<String> {
    match playbook {
        "themida_live_dump" | "live_dump_wait_text" => vec![
            "Static: empty .text / Oreans markers confirmed in ranking.".into(),
            "Live dump required — packer decrypts in its own process.".into(),
            "Poll .text growth; label runtime_dump only on size delta.".into(),
        ],
        "vmp_live_dump" => vec![
            "VMProtect markers — dump after mutation; no static VM lift.".into(),
        ],
        "upx_d" => vec![
            "If upx on PATH: upx -d -o out in.".into(),
            "Else note upx_not_installed.".into(),
        ],
        "dw_stub_offline" => vec![
            "Cs2-External-class dword [rcx+disp] stub on disk.".into(),
            "Auto-extract ops + lea target; invert offline — no spawn.".into(),
            "Verify container header dwords / magic after transform.".into(),
        ],
        "xor_recover" | "aes_ni_trace" | "chacha_recover" | "tea_recover" | "rc4_recover" => {
            vec![
                "Shapes ranked from disk opcodes/constants.".into(),
                "Auto-solve tried magic-anchored XOR / printable / inflate.".into(),
                "Only cipher hits with validated headers count as decrypted.".into(),
            ]
        }
        _ => vec![
            "Classify + entropy + imports.".into(),
            "No decrypt claim without kind=cipher transform.".into(),
        ],
    }
}

fn render_md(r: &CryptoReport) -> String {
    let mut s = String::new();
    s.push_str("# Street — Crypto Ranking (static)\n\n");
    s.push_str(&format!("- path: `{}`\n", r.path));
    s.push_str(&format!("- sha256: `{}`\n", &r.sha256[..16.min(r.sha256.len())]));
    s.push_str(&format!("- primary: **{}** (playbook `{}`)\n", r.ranking.primary, r.ranking.playbook));
    s.push_str(&format!("- decrypted: **{}**\n", r.decrypted));
    s.push_str(&format!("- entropy: {:.3}  islands: {}\n\n", r.ranking.entropy_global, r.ranking.islands));
    s.push_str("## Ranked systems\n\n");
    for (i, h) in r.ranking.hits.iter().enumerate() {
        s.push_str(&format!(
            "{}. `{}` conf={:.2} score={:.1}\n",
            i + 1,
            h.system,
            h.confidence,
            h.rank_score
        ));
        for e in h.evidence.iter().take(4) {
            s.push_str(&format!("   - {e}\n"));
        }
    }
    s.push_str("\n## Auto-solved\n\n");
    if r.solved.is_empty() {
        s.push_str("_none — shapes only, or needs live dump_\n");
    } else {
        for h in &r.solved {
            s.push_str(&format!(
                "- **{}** `{}` score={} off={:#x} decrypted={} — {}\n",
                h.cipher, h.magic, h.score, h.offset, h.decrypted, h.note
            ));
        }
    }
    s.push_str("\n## Anti-debug / tamper / crypto API (static)\n\n");
    s.push_str("Names and file offsets. A hit is a candidate, not proof the check runs.\n\n");
    render_protect(&mut s, "anti_debug", &r.protect.anti_debug);
    render_protect(&mut s, "tamper", &r.protect.tamper);
    render_protect(&mut s, "crypto_api", &r.protect.crypto_api);
    s.push_str("\n## Playbook\n\n");
    for (i, step) in r.playbook_steps.iter().enumerate() {
        s.push_str(&format!("{}. {step}\n", i + 1));
    }
    if !r.bundles.is_empty() {
        s.push_str("\n## Embedded text payload\n\n");
        s.push_str("Plaintext the host ships inside itself — inventory, not a decrypt.\n\n");
        for b in r.bundles.iter().take(24) {
            s.push_str(&format!(
                "- `{}` {:#x} {} B {} lines — {}\n",
                b.kind,
                b.offset,
                b.size,
                b.lines,
                b.first_line.replace('`', "'")
            ));
        }
    }
    if !r.residual.is_empty() {
        s.push_str("\n## Residual structure (transform ran, did not validate)\n\n");
        s.push_str("What the transform produced anyway — the lead for a second layer.\n\n");
        for f in &r.residual {
            s.push_str(&format!(
                "- **{}** off={:#x} — H {:.2}, {} printable runs / {} B\n",
                f.cipher, f.offset, f.probe.entropy, f.probe.printable_runs, f.probe.printable_bytes
            ));
            if !f.probe.header_dwords.is_empty() {
                s.push_str(&format!("  - header dwords: `{}`\n", f.probe.header_dwords.join(" ")));
            }
            if !f.probe.magics.is_empty() {
                s.push_str(&format!("  - magics: `{}`\n", f.probe.magics.join(" ")));
            }
            if !f.probe.section_names.is_empty() {
                s.push_str(&format!("  - PE section names: `{}`\n", f.probe.section_names.join(" ")));
            }
            if !f.probe.longest_run.is_empty() {
                s.push_str(&format!(
                    "  - longest run @ {:#x}: `{}`\n",
                    f.probe.longest_run_off,
                    f.probe.longest_run.replace('`', "'")
                ));
            }
            s.push_str(&format!("  - {}\n", f.probe.hint));
        }
    }
    s.push_str("\n## Notes\n\n");
    for n in &r.notes {
        s.push_str(&format!("- {n}\n"));
    }
    s
}

#[allow(dead_code)]
fn _keep_decrypt_hit(_: &DecryptHit) {}
