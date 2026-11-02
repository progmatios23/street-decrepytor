//! Static anti-debug, tamper, and crypto-API surface. Names and offsets only.

use serde::{Deserialize, Serialize};
use street_core::parse_imports;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectHit {
    pub family: String,
    pub kind: String,
    pub name: String,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectSurface {
    pub schema_version: u32,
    pub anti_debug: Vec<ProtectHit>,
    pub tamper: Vec<ProtectHit>,
    pub crypto_api: Vec<ProtectHit>,
    pub notes: Vec<String>,
}

const ANTI_DEBUG: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "DebugActiveProcess",
    "ProcessDebugPort",
    "ProcessDebugObjectHandle",
    "ProcessDebugFlags",
    "NtGlobalFlag",
    "BeingDebugged",
    "x64dbg",
    "ollydbg",
    "ida.exe",
    "cheatengine",
];

const TAMPER: &[&str] = &[
    "CheckSumMappedFile",
    "MapFileAndCheckSumW",
    "MapFileAndCheckSumA",
    "WinVerifyTrust",
    "ImageEnumerateCertificates",
    "integrity",
    "tamper",
    "file corrupted",
    "CRC32",
];

const CRYPTO_API: &[&str] = &[
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenRandom",
    "BCryptOpenAlgorithmProvider",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenerateSymmetricKey",
    "RtlEncryptMemory",
    "SystemFunction032",
];

pub fn scan_protect(data: &[u8]) -> ProtectSurface {
    let window = &data[..data.len().min(24 << 20)];
    let mut anti_debug = Vec::new();
    let mut tamper = Vec::new();
    let mut crypto_api = Vec::new();

    for e in parse_imports(window) {
        push_name(&mut anti_debug, "anti_debug", "import", &e.name, None);
        push_name(&mut tamper, "tamper", "import", &e.name, None);
        push_name(&mut crypto_api, "crypto_api", "import", &e.name, None);
    }
    scan_ascii(window, &mut anti_debug, &mut tamper, &mut crypto_api);
    scan_utf16(window, &mut anti_debug, &mut tamper, &mut crypto_api);

    anti_debug.truncate(64);
    tamper.truncate(64);
    crypto_api.truncate(64);

    let mut notes = vec![
        "static disk surface — import names and bounded strings".into(),
        "observation only: name + offset. no bypass, hook, or rewrite".into(),
        "a listed API is a candidate check, not proof it runs".into(),
    ];
    if anti_debug.is_empty() && tamper.is_empty() {
        notes.push("no named anti-debug or tamper surface on disk — packer may hide it until runtime".into());
    }

    ProtectSurface {
        schema_version: 1,
        anti_debug,
        tamper,
        crypto_api,
        notes,
    }
}

fn push_name(out: &mut Vec<ProtectHit>, family: &str, kind: &str, name: &str, off: Option<u64>) {
    let needles: &[&str] = match family {
        "anti_debug" => ANTI_DEBUG,
        "tamper" => TAMPER,
        _ => CRYPTO_API,
    };
    let lower = name.to_ascii_lowercase();
    let hit = needles
        .iter()
        .filter(|n| lower.contains(&n.to_ascii_lowercase()))
        .max_by_key(|n| n.len());
    if let Some(hit) = hit {
        if out.iter().any(|h| h.name.eq_ignore_ascii_case(hit) && h.kind == kind && h.file_offset == off)
        {
            return;
        }
        out.push(ProtectHit {
            family: family.into(),
            kind: kind.into(),
            name: (*hit).into(),
            file_offset: off,
        });
    }
}

fn scan_ascii(
    data: &[u8],
    anti: &mut Vec<ProtectHit>,
    tamper: &mut Vec<ProtectHit>,
    crypto: &mut Vec<ProtectHit>,
) {
    let mut cur = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if (32..127).contains(&b) {
            if cur.is_empty() {
                start = i;
            }
            cur.push(b);
            if cur.len() > 240 {
                flush_ascii(&cur, start, anti, tamper, crypto);
                cur.clear();
            }
        } else if !cur.is_empty() {
            if cur.len() >= 6 {
                flush_ascii(&cur, start, anti, tamper, crypto);
            }
            cur.clear();
        }
    }
    if cur.len() >= 6 {
        flush_ascii(&cur, start, anti, tamper, crypto);
    }
}

fn flush_ascii(
    cur: &[u8],
    start: usize,
    anti: &mut Vec<ProtectHit>,
    tamper: &mut Vec<ProtectHit>,
    crypto: &mut Vec<ProtectHit>,
) {
    let Ok(s) = std::str::from_utf8(cur) else {
        return;
    };
    let off = Some(start as u64);
    push_name(anti, "anti_debug", "string", s, off);
    push_name(tamper, "tamper", "string", s, off);
    push_name(crypto, "crypto_api", "string", s, off);
}

fn scan_utf16(
    data: &[u8],
    anti: &mut Vec<ProtectHit>,
    tamper: &mut Vec<ProtectHit>,
    crypto: &mut Vec<ProtectHit>,
) {
    for needle in ANTI_DEBUG.iter().chain(TAMPER).chain(CRYPTO_API) {
        let enc: Vec<u8> = needle.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        if enc.len() < 8 || data.len() < enc.len() {
            continue;
        }
        if let Some(rel) = data.windows(enc.len()).position(|w| w == enc) {
            let family = if ANTI_DEBUG.contains(needle) {
                "anti_debug"
            } else if TAMPER.contains(needle) {
                "tamper"
            } else {
                "crypto_api"
            };
            let bucket = match family {
                "anti_debug" => &mut *anti,
                "tamper" => &mut *tamper,
                _ => &mut *crypto,
            };
            if bucket.iter().any(|h| h.name == *needle && h.kind == "utf16") {
                continue;
            }
            bucket.push(ProtectHit {
                family: family.into(),
                kind: "utf16".into(),
                name: (*needle).into(),
                file_offset: Some(rel as u64),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_debugger_and_checksum_strings() {
        let mut blob = vec![0u8; 32];
        blob.extend_from_slice(b"\0IsDebuggerPresent\0");
        blob.extend_from_slice(b"CheckSumMappedFile\0");
        blob.extend_from_slice(b"BCryptEncrypt\0");
        let s = scan_protect(&blob);
        assert!(s.anti_debug.iter().any(|h| h.name == "IsDebuggerPresent"));
        assert!(s.tamper.iter().any(|h| h.name == "CheckSumMappedFile"));
        assert!(s.crypto_api.iter().any(|h| h.name == "BCryptEncrypt"));
    }
}
