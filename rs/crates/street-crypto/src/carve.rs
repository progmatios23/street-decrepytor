//! Carve embedded MZ/PE and high-value blobs from disk — static only.

use serde::{Deserialize, Serialize};
use street_core::sha256_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedPe {
    pub offset: u64,
    pub size: usize,
    pub sha256: String,
    pub machine: String,
    pub sections: u16,
    pub entry_rva: u32,
}

/// A contiguous printable-text payload embedded in the host — an embedded script,
/// config, or persona. `onx_cmd.exe` carries a whole agent toolkit this way
/// (proxy.py, inject_onx.py, .bat launchers, scaffold_onx_agent.ps1, opencode.json,
/// the ONX persona), and `carve_embedded_pe` reported none of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedText {
    pub offset: u64,
    pub size: usize,
    pub sha256: String,
    pub kind: String,
    pub lines: usize,
    pub first_line: String,
}

pub fn carve_embedded_pe(data: &[u8], max: usize) -> Vec<(CarvedPe, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 1usize; // skip outer MZ at 0 when present
    while i + 0x40 < data.len() && out.len() < max {
        if &data[i..i + 2] != b"MZ" {
            i += 1;
            continue;
        }
        let e = u32::from_le_bytes(data[i + 0x3C..i + 0x40].try_into().unwrap()) as usize;
        if e < 0x40 || e > 0x1000 || i + e + 0x18 >= data.len() {
            i += 1;
            continue;
        }
        if &data[i + e..i + e + 4] != b"PE\0\0" {
            i += 1;
            continue;
        }
        let machine = u16::from_le_bytes(data[i + e + 4..i + e + 6].try_into().unwrap());
        let nsec = u16::from_le_bytes(data[i + e + 6..i + e + 8].try_into().unwrap());
        let opt = u16::from_le_bytes(data[i + e + 0x14..i + e + 0x16].try_into().unwrap()) as usize;
        let magic = u16::from_le_bytes(data[i + e + 0x18..i + e + 0x1A].try_into().unwrap());
        let ep = u32::from_le_bytes(data[i + e + 0x18 + 16..i + e + 0x18 + 20].try_into().unwrap());
        // estimate size from last section
        let sec = i + e + 0x18 + opt;
        let mut end = i + e + 0x18 + opt + nsec as usize * 40;
        for s in 0..nsec.min(96) {
            let o = sec + s as usize * 40;
            if o + 40 > data.len() {
                break;
            }
            let rsize = u32::from_le_bytes(data[o + 16..o + 20].try_into().unwrap()) as usize;
            let roff = u32::from_le_bytes(data[o + 20..o + 24].try_into().unwrap()) as usize;
            end = end.max(i + roff + rsize);
        }
        end = end.min(data.len()).max(i + 0x200);
        let blob = data[i..end].to_vec();
        if blob.len() < 0x200 {
            i += 1;
            continue;
        }
        out.push((
            CarvedPe {
                offset: i as u64,
                size: blob.len(),
                sha256: sha256_bytes(&blob),
                machine: format!("0x{machine:x}"),
                sections: nsec,
                entry_rva: ep,
            },
            blob,
        ));
        i = end;
        let _ = magic;
    }
    out
}

/// Find contiguous printable-text payloads (scripts, configs, personas).
///
/// A run is a maximal stretch of printable/whitespace bytes, tolerating up to two
/// stray non-printable bytes so a single embedded file is not split in two. Runs
/// shorter than `min_len` are ignored; at most `max` are returned, longest first.
pub fn carve_embedded_text(data: &[u8], min_len: usize, max: usize) -> Vec<(CarvedText, Vec<u8>)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if !is_text_byte(data[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let mut stray = 0usize;
        let mut last_good = i;
        while i < data.len() {
            if is_text_byte(data[i]) {
                stray = 0;
                last_good = i;
                i += 1;
            } else if stray < 2 {
                stray += 1;
                i += 1;
            } else {
                break;
            }
        }
        let end = last_good + 1;
        if end > start && end - start >= min_len {
            runs.push((start, end));
        }
        i = end.max(start + 1);
    }

    let mut out: Vec<(CarvedText, Vec<u8>)> = Vec::new();
    for (start, end) in runs {
        let blob = data[start..end].to_vec();
        let kind = classify_text_blob(&blob);
        if kind == "noise" {
            continue;
        }
        let first_line = blob
            .split(|&b| b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).trim().chars().take(120).collect::<String>())
            .unwrap_or_default();
        let lines = blob.iter().filter(|&&b| b == b'\n').count() + 1;
        out.push((
            CarvedText {
                offset: start as u64,
                size: blob.len(),
                sha256: sha256_bytes(&blob),
                kind,
                lines,
                first_line,
            },
            blob,
        ));
    }
    out.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    out.truncate(max);
    out
}

fn is_text_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\r' | b'\n')
}

/// Best-effort classification of an embedded text payload by its strongest marker.
fn classify_text_blob(blob: &[u8]) -> String {
    let head = &blob[..blob.len().min(4096)];
    let s = String::from_utf8_lossy(head);
    let trimmed = s.trim_start();
    let lines: Vec<&str> = s.lines().take(24).collect();
    let has = |n: &str| s.contains(n);

    // Batch: @echo off / REM / goto :label / %VAR% expansion
    if trimmed.starts_with("@echo") || (has("REM ") && (has("goto :") || has("set \""))) {
        return "batch".into();
    }
    // PowerShell
    if has("$ErrorActionPreference")
        || has("param(")
        || (has("powershell -NoProfile") || has("ExecutionPolicy Bypass"))
        || trimmed.starts_with("function ")
    {
        return "powershell".into();
    }
    // JSON config
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && has("\":") {
        return "json".into();
    }
    // Python
    let py_markers = lines
        .iter()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("import ")
                || t.starts_with("from ")
                || t.starts_with("def ")
                || t.starts_with("async def ")
                || t.starts_with("class ")
                || t.starts_with("@app.")
        })
        .count();
    if trimmed.starts_with("#!") || py_markers >= 3 || (has("\"\"\"") && py_markers >= 1) {
        return "python".into();
    }
    // Persona / system prompt: prose with sentence structure, low symbol density
    let alpha = blob.iter().filter(|b| b.is_ascii_alphabetic()).count() as f64;
    let sym = blob
        .iter()
        .filter(|b| matches!(b, b'{' | b'}' | b';' | b'<' | b'>' | b'|' | b'\\'))
        .count() as f64;
    let n = blob.len() as f64;
    if lines.len() >= 6 && alpha / n > 0.55 && sym / n < 0.01 && has("You are ") {
        return "persona".into();
    }
    if lines.len() >= 6 && alpha / n > 0.55 && sym / n < 0.005 {
        return "prose".into();
    }
    "text".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carves_python_and_batch_between_binary_padding() {
        let py = b"import os\nimport sys\nfrom pathlib import Path\n\ndef main():\n    print('hi')\n";
        let bat = b"@echo off\nREM launcher\nset \"X=1\"\ngoto :launch\n";
        let mut data = vec![0x00u8; 64];
        data.extend_from_slice(py);
        data.extend_from_slice(&[0xFF; 16]);
        data.extend_from_slice(bat);
        let got = carve_embedded_text(&data, 32, 8);
        let kinds: Vec<&str> = got.iter().map(|(c, _)| c.kind.as_str()).collect();
        assert!(kinds.contains(&"python"), "{kinds:?}");
        assert!(kinds.contains(&"batch"), "{kinds:?}");
    }

    #[test]
    fn ignores_short_or_noise_runs() {
        let data = b"hi\0\0\0\0there".to_vec();
        let got = carve_embedded_text(&data, 512, 8);
        assert!(got.is_empty(), "{got:?}");
    }
}
