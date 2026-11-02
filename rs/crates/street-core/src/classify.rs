use crate::arch::Arch;
use crate::entropy::printable_ratio;
use crate::family::LangFamily;
use crate::image::parse_elf_header;
use crate::pe::parse_pe;
use crate::{sha256_bytes, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactProfile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub family: LangFamily,
    pub arch: Arch,
    pub format: String,
    pub confidence: f32,
    pub signals: Vec<String>,
    pub multi_build_hints: Vec<String>,
    pub protector_candidates: Vec<serde_json::Value>,
    pub pe_info: serde_json::Value,
    /// Static facts that constrain live analysis: whether the binary demands
    /// elevation, and how many direct-syscall sites it contains. Both are
    /// properties a live tracer needs to know *before* it tries to run the
    /// target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_profile: Option<crate::exec_profile::ExecutionProfile>,
    pub schema_version: u32,
}

pub fn classify_path(path: &Path) -> Result<ArtifactProfile> {
    let data = std::fs::read(path)?;
    let mut p = classify_bytes(&data, Some(path))?;
    p.path = path.display().to_string();
    p.size = data.len() as u64;
    Ok(p)
}

pub fn classify_bytes(data: &[u8], path: Option<&Path>) -> Result<ArtifactProfile> {
    let sha = sha256_bytes(data);
    let path_s = path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<bytes>".into());
    let size = data.len() as u64;

    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return Ok(classify_pe(data, &path_s, size, sha));
    }
    if let Some((arch, _)) = parse_elf_header(data) {
        let mut family = LangFamily::NativeElf;
        let mut signals = vec![];
        let window = &data[..data.len().min(1 << 20)];
        if window.windows(12).any(|w| w == b"Go build ID:") {
            family = LangFamily::Go;
            signals.push("go_on_elf".into());
        }
        return Ok(ArtifactProfile {
            path: path_s,
            size,
            sha256: sha,
            family,
            arch,
            format: "elf".into(),
            confidence: 0.9,
            signals,
            multi_build_hints: vec![],
            protector_candidates: vec![],
            pe_info: serde_json::json!({}),
            exec_profile: None,
            schema_version: crate::SCHEMA_VERSION,
        });
    }
    if data.len() >= 2 && &data[0..2] == b"PK" {
        let mut family = LangFamily::Archive;
        let mut signals = vec!["zip_container".into()];
        let mut conf = 0.7f32;
        if data.windows(21).any(|w| w == b"META-INF/MANIFEST.MF")
            || data.windows(6).any(|w| w == b".class")
            || data.windows(4).any(|w| w == b"\xca\xfe\xba\xbe")
        {
            family = LangFamily::Java;
            signals.push("jar_class".into());
            conf = 0.9;
        }
        if data.windows(14).any(|w| w == b"PYZ-00.pyz") || data.windows(8).any(|w| w == b"MEI\x0c\x0b\x0a\x0b") {
            family = LangFamily::Python;
            signals.push("pyinstaller_zip".into());
            conf = 0.85;
        }
        return Ok(ArtifactProfile {
            path: path_s,
            size,
            sha256: sha,
            family,
            arch: Arch::Unknown,
            format: "zip".into(),
            confidence: conf,
            signals,
            multi_build_hints: vec![],
            protector_candidates: vec![],
            pe_info: serde_json::json!({}),
            exec_profile: None,
            schema_version: crate::SCHEMA_VERSION,
        });
    }
    if data.len() >= 16 && &data[0..4] == b"\xca\xfe\xba\xbe" {
        return Ok(ArtifactProfile {
            path: path_s,
            size,
            sha256: sha,
            family: LangFamily::Java,
            arch: Arch::Unknown,
            format: "class".into(),
            confidence: 0.95,
            signals: vec!["java_class_magic".into()],
            multi_build_hints: vec![],
            protector_candidates: vec![],
            pe_info: serde_json::json!({}),
            exec_profile: None,
            schema_version: crate::SCHEMA_VERSION,
        });
    }
    if data.len() >= 16 && (data.starts_with(b"\x16\r\r\n") || data.windows(8).any(|w| w == b"\x00\x00\x00\x00\xe3")) {
        // pyc-ish
        return Ok(ArtifactProfile {
            path: path_s,
            size,
            sha256: sha,
            family: LangFamily::Python,
            arch: Arch::Unknown,
            format: "pyc".into(),
            confidence: 0.6,
            signals: vec!["pyc_hint".into()],
            multi_build_hints: vec![],
            protector_candidates: vec![],
            pe_info: serde_json::json!({}),
            exec_profile: None,
            schema_version: crate::SCHEMA_VERSION,
        });
    }

    Ok(ArtifactProfile {
        path: path_s,
        size,
        sha256: sha,
        family: LangFamily::Unknown,
        arch: Arch::Unknown,
        format: "unknown".into(),
        confidence: 0.1,
        signals: vec!["no_magic".into()],
        multi_build_hints: vec![],
        protector_candidates: vec![],
        pe_info: serde_json::json!({}),
        exec_profile: None,
        schema_version: crate::SCHEMA_VERSION,
    })
}

/// Count **validated** embedded PE images: an `MZ` whose `e_lfanew` points at a
/// `PE\0\0` signature inside the file.
///
/// Counting bare `MZ` byte pairs is meaningless on high-entropy data — a 45 MB
/// encrypted blob contains roughly 693 of them purely by chance, so a threshold
/// of "more than 3" fires on essentially every packed binary and reports a
/// `possible_multi_pe_bundle` that does not exist. Requiring the PE signature
/// makes the signal mean what its name claims.
fn count_embedded_pe(data: &[u8]) -> usize {
    let mut n = 0usize;
    // Start at 1: a PE at offset 0 is the image itself, not an embedded one.
    let mut i = 1usize;
    while i + 0x40 <= data.len() {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let e = u32::from_le_bytes([data[i + 0x3C], data[i + 0x3D], data[i + 0x3E], data[i + 0x3F]])
                as usize;
            let sig = i + e;
            if e >= 0x40 && sig + 4 <= data.len() && &data[sig..sig + 4] == b"PE\0\0" {
                n += 1;
                // Skip past this header; the embedded image is counted once.
                i += 0x40;
                continue;
            }
        }
        i += 1;
    }
    n
}

/// Flag sections whose *content* contradicts their *name*.
///
/// The pattern on `onx_cmd.exe`: a section called `.reloc` whose PE
/// `BASE_RELOCATION` data directory is `rva=0 size=0`, marked RWX, holding a
/// 556 KB encrypted blob and a dword-op decryptor stub. The name is legitimate
/// and the section is genuinely executable-permissioned, so a name filter and an
/// executability filter both wave it through — the anomaly is the *combination*:
/// a metadata-named section that disclaims itself, is writable+executable, and
/// carries high-entropy data. That is the single most load-bearing signal on the
/// file and it was previously invisible.
fn section_anomalies(img: &crate::image::LoadedImage, data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for s in &img.sections {
        let start = s.raw_off as usize;
        let end = (start + s.raw_size as usize).min(data.len());
        if end <= start {
            continue;
        }
        let size = end - start;
        let meta_name = matches!(
            s.name.as_str(),
            ".reloc" | ".rsrc" | ".pdata" | ".edata" | ".idata" | ".debug"
        ) || s.name.starts_with(".debug");
        // A whole-section average is defeated by padding: `.reloc` on this target
        // is 56% zero bytes, so its average entropy sits near 3.9 even though the
        // live region runs at 7.9. Measure the densest 4 KiB window — that is what
        // "this section hides encrypted data" actually means.
        let h = if size >= 0x4000 {
            data[start..end]
                .chunks(0x1000)
                .filter(|c| c.len() >= 0x1000)
                .map(crate::entropy::shannon)
                .fold(0.0f64, f64::max)
        } else {
            0.0
        };
        if meta_name && size >= 0x4000 && h > 7.5 {
            out.push(format!(
                "high_entropy_metadata_section: {} raw {:#x} peak-window H {:.2} — content is not {} data",
                s.name, s.raw_size, h, s.name
            ));
        }
        if meta_name && s.writable() && s.executable() {
            out.push(format!(
                "rwx_metadata_section: {} chars {:#010x} — writable+executable under a metadata name",
                s.name, s.chars
            ));
        }
    }
    out
}

fn classify_pe(data: &[u8], path: &str, size: u64, sha: String) -> ArtifactProfile {
    let mut signals = Vec::new();
    let mut family = LangFamily::NativePe;
    let mut conf = 0.55f32;
    let mut multi = Vec::new();
    let mut protectors = Vec::new();

    let img = match parse_pe(data) {
        Ok(i) => i,
        Err(_) => {
            return ArtifactProfile {
                path: path.into(),
                size,
                sha256: sha,
                family: LangFamily::Unknown,
                arch: Arch::Unknown,
                format: "mz_no_pe".into(),
                confidence: 0.2,
                signals: vec!["mz_without_pe".into()],
                multi_build_hints: vec![],
                protector_candidates: vec![],
                pe_info: serde_json::json!({}),
                exec_profile: Some(crate::exec_profile::analyze(data)),
                schema_version: crate::SCHEMA_VERSION,
            };
        }
    };

    let names: Vec<String> = img.section_names().into_iter().map(|s| s.to_string()).collect();
    let virtual_only = img.virtual_only_count();
    if virtual_only > 0 {
        signals.push(format!("virtual_only_sections={virtual_only}"));
        conf += 0.05;
    }

    let anomalies = section_anomalies(&img, data);
    if !anomalies.is_empty() {
        conf += 0.05;
    }
    signals.extend(anomalies);

    let window = &data[..data.len().min(4 << 20)];
    let window_l = String::from_utf8_lossy(window).to_ascii_lowercase();

    if img.clr_rva != 0 && img.clr_size != 0 {
        family = LangFamily::Dotnet;
        signals.push("clr_directory_present".into());
        conf = 0.9;
        if window_l.contains("mscoree.dll") || window.windows(11).any(|w| w == b"_CorExeMain") {
            signals.push("mscoree_bootstrap".into());
        }
    }

    if window.windows(12).any(|w| w == b"runtime.main")
        || window.windows(12).any(|w| w == b"Go build ID:")
        || window.windows(14).any(|w| w == b"runtime.gopanic")
    {
        family = if family == LangFamily::NativePe {
            LangFamily::Go
        } else {
            LangFamily::Mixed
        };
        signals.push("go_runtime_marker".into());
        conf = conf.max(0.85);
    }

    if window.windows(13).any(|w| w == b"rustc-version")
        || (window.windows(6).any(|w| w == b".llvm.") && window.windows(14).any(|w| w == b"RUST_BACKTRACE"))
    {
        signals.push("rust_marker".into());
        if family == LangFamily::NativePe {
            family = LangFamily::Rust;
            conf = conf.max(0.8);
        }
    }
    if window.windows(11).any(|w| w == b"panicked at") {
        signals.push("rust_panic_path".into());
        if family == LangFamily::NativePe {
            family = LangFamily::Rust;
            conf = conf.max(0.75);
        }
    }

    if family == LangFamily::Dotnet && window_l.contains("kernel32.dll") && window_l.contains("msvcp") {
        family = LangFamily::CppCli;
        signals.push("cpp_cli_mixed_hints".into());
    }

    if window.windows(8).any(|w| w == b"WebView2") || window_l.contains("tauri") {
        signals.push("tauri_webview2".into());
        multi.push("desktop_webview_bundle".into());
        if family == LangFamily::NativePe {
            family = LangFamily::Rust;
            conf = conf.max(0.78);
        }
    }

    if window.windows(13).any(|w| w == b"technique_id=T") || window.windows(6).any(|w| w == b"Sysmon") {
        signals.push("dfir_mitre_rules_embedded".into());
        conf = conf.max(0.7);
    }

    let pe_count = count_embedded_pe(data);
    if pe_count > 0 {
        multi.push(format!("embedded_pe_count~{pe_count}"));
        signals.push("possible_multi_pe_bundle".into());
    }

    if virtual_only >= 2 {
        protectors.push(serde_json::json!({
            "name": "runtime_section_decryptor",
            "reason": "multiple zero-raw sections (common Themida/VMProtect/custom)",
            "confidence": 0.45
        }));
    }
    if names.iter().any(|n| {
        let l = n.to_ascii_lowercase();
        matches!(l.as_str(), ".themida" | ".winlice" | ".vmp0" | ".vmp1" | "themida")
    }) {
        protectors.push(serde_json::json!({
            "name": "named_protector_section",
            "sections": names,
            "confidence": 0.7
        }));
    }

    let sample = if data.len() > 0x9000 {
        &data[0x1000..0x1000 + 0x8000]
    } else {
        data
    };
    let ratio = printable_ratio(sample);
    if ratio < 0.15 && !sample.is_empty() {
        signals.push("low_printable_ratio_packed_likely".into());
        conf = (conf + 0.05).min(0.95);
    }

    ArtifactProfile {
        path: path.into(),
        size,
        sha256: sha,
        family,
        arch: img.arch,
        format: "pe".into(),
        confidence: conf.min(0.99),
        signals,
        multi_build_hints: multi,
        protector_candidates: protectors,
        pe_info: serde_json::json!({
            "machine": format!("0x{:x}", img.machine),
            "sections": img.sections.len(),
            "pe32plus": img.is_64,
            "clr_rva": img.clr_rva,
            "clr_size": img.clr_size,
            "section_names": names,
            "entry_rva": img.entry_rva,
            "image_base": img.image_base,
            "printable_ratio_sample": (ratio * 10000.0).round() / 10000.0,
        }),
        exec_profile: Some(crate::exec_profile::analyze(data)),
        schema_version: crate::SCHEMA_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::minimal_pe64;

    #[test]
    fn pe_classifies() {
        let pe = minimal_pe64(b"\x90\x90\xc3", ".text");
        let p = classify_bytes(&pe, None).unwrap();
        assert_eq!(p.format, "pe");
        assert!(matches!(
            p.family,
            LangFamily::NativePe | LangFamily::Unknown | LangFamily::Rust | LangFamily::Go
        ));
        assert_eq!(p.arch, Arch::X64);
    }

    #[test]
    fn zip_jar_hint() {
        // local file header + names
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[0u8; 26]);
        z.extend_from_slice(b"META-INF/MANIFEST.MF");
        z.extend_from_slice(b"\xca\xfe\xba\xbe");
        z.extend_from_slice(b"com/x/A.class");
        let p = classify_bytes(&z, None).unwrap();
        assert_eq!(p.family, LangFamily::Java);
    }

    /// Build a minimal valid PE: `MZ` at offset 0, `e_lfanew` -> `PE\0\0`.
    fn fake_pe(prefix: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(prefix);
        let base = v.len();
        let mut hdr = vec![0u8; 0x40];
        hdr[0] = b'M';
        hdr[1] = b'Z';
        // e_lfanew = 0x40, relative to the MZ.
        hdr[0x3C] = 0x40;
        v.extend_from_slice(&hdr);
        v.extend_from_slice(b"PE\0\0");
        v.extend_from_slice(&[0u8; 0x20]);
        let _ = base;
        v
    }

    #[test]
    fn a_bare_mz_pair_is_not_an_embedded_pe() {
        // High-entropy data contains `MZ` byte pairs by chance. Counting them
        // reported hundreds of phantom embedded images on an encrypted blob.
        let mut noise: Vec<u8> = Vec::new();
        for i in 0..5000u32 {
            noise.push((i.wrapping_mul(2654435761) >> 16) as u8);
        }
        noise.extend_from_slice(b"MZ\x00\x00\x00\x00");
        noise.extend_from_slice(b"MZ\x11\x22\x33\x44");
        assert_eq!(count_embedded_pe(&noise), 0);
    }

    #[test]
    fn a_real_appended_pe_is_counted() {
        let mut v = fake_pe(b"");
        v.extend_from_slice(&fake_pe(b""));
        // One PE at offset 0 (the image itself) plus one appended.
        assert_eq!(count_embedded_pe(&v), 1);
    }

    #[test]
    fn the_image_itself_is_not_an_embedded_pe() {
        assert_eq!(count_embedded_pe(&fake_pe(b"")), 0);
    }

    #[test]
    fn a_truncated_candidate_does_not_panic() {
        // `MZ` near the end, with no room for e_lfanew.
        let mut v = vec![0u8; 10];
        v[8] = b'M';
        v[9] = b'Z';
        assert_eq!(count_embedded_pe(&v), 0);
    }

    #[test]
    fn an_out_of_range_e_lfanew_is_rejected() {
        let mut v = fake_pe(b"");
        // Point e_lfanew far past the end of the file.
        v[0x3C] = 0xFF;
        v[0x3D] = 0xFF;
        v[0x3E] = 0xFF;
        v[0x3F] = 0x7F;
        assert_eq!(count_embedded_pe(&v), 0);
    }
}
