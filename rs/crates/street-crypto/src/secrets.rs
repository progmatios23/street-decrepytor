//! Cleartext credential scan — static only.
//!
//! `onx_cmd.exe` embeds `sk-zw2x5…` — a live API key — as a plain `.rdata` string
//! and the tool reported nothing. A host that ships its own credentials in the
//! clear is a finding in its own right, so this pass reports them.
//!
//! Scans both the ASCII and the UTF-16LE view of the image, because MSVC widens
//! wide-string literals to UTF-16 and a scanner that only reads ASCII misses them.
//! Values are masked (`masked`) and hashed (`sha256`) so a report can be shared
//! without republishing the secret; `raw` is populated only when the caller asks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use street_core::sha256_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHit {
    pub kind: String,
    pub offset: u64,
    pub encoding: String,
    pub masked: String,
    pub length: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretReport {
    pub hits: Vec<SecretHit>,
    pub by_kind: BTreeMap<String, usize>,
}

/// `(prefix, minimum token chars after the prefix)`. Lengths are deliberately
/// loose: a short-but-real key is a finding, and the mask hides the rest.
const PREFIXES: &[(&str, usize)] = &[
    ("sk-ant-", 16),
    ("sk-proj-", 16),
    ("sk_live_", 16),
    ("sk_test_", 16),
    ("rk_live_", 16),
    ("pk_live_", 16),
    ("sk-", 16),
    ("github_pat_", 20),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("glpat-", 16),
    ("dckr_pat_", 16),
    ("npm_", 16),
    ("xoxb-", 8),
    ("xoxp-", 8),
    ("xoxa-", 8),
    ("xoxr-", 8),
    ("xoxs-", 8),
    ("AKIA", 16),
    ("ASIA", 16),
    ("AIza", 20),
    ("SG.", 16),
];

/// Keyword → token. Catches `"api_key": "…"`, `password=…`, `Bearer …`, and the
/// like when the value has no vendor prefix.
const KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret_key",
    "secret",
    "password",
    "passwd",
    "access_token",
    "auth_token",
    "token",
    "bearer",
    "authorization",
];

#[inline]
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'~'
}

fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 10 {
        return "*".repeat(n);
    }
    let head: String = s.chars().take(6).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail} (len {n})")
}

fn push_hit(
    hits: &mut Vec<SecretHit>,
    seen: &mut std::collections::HashSet<(u64, String)>,
    kind: &str,
    encoding: &str,
    offset: u64,
    token: &str,
    reveal: bool,
) {
    if !seen.insert((offset, kind.to_string())) {
        return;
    }
    hits.push(SecretHit {
        kind: kind.to_string(),
        offset,
        encoding: encoding.to_string(),
        masked: mask(token),
        length: token.len(),
        sha256: sha256_bytes(token.as_bytes()),
        raw: if reveal { Some(token.to_string()) } else { None },
    });
}

/// First-byte index over [`PREFIXES`], so the scan touches each byte once instead
/// of once per pattern.
fn prefix_map() -> std::collections::HashMap<u8, Vec<(&'static str, usize)>> {
    let mut m: std::collections::HashMap<u8, Vec<(&'static str, usize)>> =
        std::collections::HashMap::new();
    for &(p, n) in PREFIXES {
        m.entry(p.as_bytes()[0]).or_default().push((p, n));
    }
    m
}

/// First-byte index over [`KEYWORDS`], lowercased (matching is case-insensitive).
fn keyword_map() -> std::collections::HashMap<u8, Vec<&'static str>> {
    let mut m: std::collections::HashMap<u8, Vec<&'static str>> = std::collections::HashMap::new();
    for kw in KEYWORDS {
        m.entry(kw.as_bytes()[0].to_ascii_lowercase())
            .or_default()
            .push(kw);
    }
    m
}

/// Scan one byte view. `stride`/`base` map a byte index back to the file offset
/// (1 for ASCII, 2 for a UTF-16LE low-byte view).
fn scan_view(
    view: &[u8],
    base: usize,
    stride: usize,
    encoding: &str,
    reveal: bool,
    hits: &mut Vec<SecretHit>,
    seen: &mut std::collections::HashSet<(u64, String)>,
) {
    let at = |i: usize| (base + i * stride) as u64;

    // 1) vendor prefixes
    let pm = prefix_map();
    for i in 0..view.len() {
        let Some(cands) = pm.get(&view[i]) else {
            continue;
        };
        for &(p, min_extra) in cands {
            let pb = p.as_bytes();
            if i + pb.len() > view.len() || &view[i..i + pb.len()] != pb {
                continue;
            }
            let mut j = i + pb.len();
            while j < view.len() && is_token(view[j]) {
                j += 1;
            }
            if j - (i + pb.len()) >= min_extra {
                if let Ok(tok) = std::str::from_utf8(&view[i..j]) {
                    let kind = if p.starts_with("AKIA") || p.starts_with("ASIA") {
                        "aws_access_key_id"
                    } else {
                        "vendor_api_key"
                    };
                    push_hit(hits, seen, kind, encoding, at(i), tok, reveal);
                }
            }
        }
    }

    // 2) keyword-context
    let km = keyword_map();
    for i in 0..view.len() {
        let Some(cands) = km.get(&view[i].to_ascii_lowercase()) else {
            continue;
        };
        for kw in cands {
            let kb = kw.as_bytes();
            let m = kb.len();
            if i + m > view.len() || !view[i..i + m].eq_ignore_ascii_case(kb) {
                continue;
            }
            let mut j = i + m;
            // Skip the run of delimiters between key and value. A quoted value
            // (`"api_key": "…"`) puts *two* quotes and a colon in that run, so a
            // fixed separator count walks past the opening quote and lands on it,
            // where the token scan then reads zero chars.
            let mut skipped = 0;
            while j < view.len()
                && skipped < 6
                && matches!(view[j], b'=' | b':' | b' ' | b'\t' | b'"' | b'\'')
            {
                j += 1;
                skipped += 1;
            }
            let start = j;
            while j < view.len() && is_token(view[j]) {
                j += 1;
            }
            if j - start >= 12 {
                if let Ok(tok) = std::str::from_utf8(&view[start..j]) {
                    push_hit(hits, seen, "keyword_context", encoding, at(start), tok, reveal);
                }
            }
        }
    }

    // 3) URL-embedded credentials  scheme://user:pass@host
    let mut i = 0usize;
    while i + 3 < view.len() {
        if &view[i..i + 3] == b"://" {
            let s = i + 3;
            let mut j = s;
            let mut colon = None;
            while j < view.len() && j - s < 128 {
                match view[j] {
                    b'@' => break,
                    b':' if colon.is_none() => colon = Some(j),
                    b'/' | b' ' | b'"' | b'\'' | b'\n' | b'\r' => {
                        j = s;
                        break;
                    }
                    _ => {}
                }
                j += 1;
            }
            if j > s && j < view.len() && view[j] == b'@' {
                if let Some(c) = colon {
                    if c > s && j > c + 1 {
                        if let Ok(tok) = std::str::from_utf8(&view[c + 1..j]) {
                            push_hit(hits, seen, "url_credential", encoding, at(c + 1), tok, reveal);
                        }
                    }
                }
            }
            i = j.max(i + 3);
        } else {
            i += 1;
        }
    }

    // 4) PEM private keys
    const PEM: &[u8] = b"-----BEGIN ";
    let mut k = 0usize;
    while k + PEM.len() < view.len() {
        if &view[k..k + PEM.len()] == PEM {
            if let Some(endrel) = view[k..].windows(16).position(|w| w == b"PRIVATE KEY-----") {
                let tok = String::from_utf8_lossy(&view[k..k + endrel + 16]).into_owned();
                push_hit(hits, seen, "pem_private_key", encoding, at(k), &tok, reveal);
                k += endrel + 16;
                continue;
            }
        }
        k += 1;
    }
}

/// Extract UTF-16LE runs into a low-byte view, returning `(view, base)` pairs.
fn utf16_views(data: &[u8]) -> Vec<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 < data.len() {
        // a UTF-16LE printable run starts with a printable byte followed by 0x00
        if data[i + 1] == 0 && data[i].is_ascii_graphic() {
            let start = i;
            let mut j = i;
            let mut low = Vec::new();
            while j + 1 < data.len() && data[j + 1] == 0 && (data[j].is_ascii_graphic() || data[j] == b' ') {
                low.push(data[j]);
                j += 2;
            }
            if low.len() >= 12 {
                out.push((low, start));
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
    out
}

/// Scan `data` for cleartext credentials. `reveal` includes the raw value.
pub fn scan_secrets(data: &[u8], reveal: bool) -> SecretReport {
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::new();

    scan_view(data, 0, 1, "ascii", reveal, &mut hits, &mut seen);
    for (view, base) in utf16_views(data) {
        scan_view(&view, base, 2, "utf16le", reveal, &mut hits, &mut seen);
    }

    hits.sort_by_key(|h| h.offset);
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for h in &hits {
        *by_kind.entry(h.kind.clone()).or_insert(0) += 1;
    }
    SecretReport { hits, by_kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_openai_style_key_and_masks_it() {
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(b"sk-abcdefghijklmnopqrstuvwx1234");
        buf.extend_from_slice(&[0u8; 16]);
        let r = scan_secrets(&buf, false);
        assert!(r.hits.iter().any(|h| h.kind == "vendor_api_key"), "{:?}", r.hits);
        let h = &r.hits[0];
        assert!(h.masked.contains('…'), "{}", h.masked);
        assert!(h.raw.is_none());
    }

    #[test]
    fn finds_utf16_key() {
        let s = "sk-utf16abcdefghijklmnopqrst";
        let mut buf = vec![0u8; 8];
        for c in s.bytes() {
            buf.push(c);
            buf.push(0);
        }
        let r = scan_secrets(&buf, false);
        assert!(
            r.hits.iter().any(|h| h.encoding == "utf16le"),
            "{:?}",
            r.hits
        );
    }

    #[test]
    fn keyword_context_and_url_creds() {
        let buf = b"xxxx \"api_key\": \"abcdefghijklmnop1234\" yyyy https://user:hunter2hunter2@host/p";
        let r = scan_secrets(buf, false);
        let kinds: Vec<&str> = r.hits.iter().map(|h| h.kind.as_str()).collect();
        assert!(kinds.contains(&"keyword_context"), "{kinds:?}");
        assert!(kinds.contains(&"url_credential"), "{kinds:?}");
    }

    #[test]
    fn reveal_includes_raw() {
        let buf = b"sk-abcdefghijklmnopqrstuvwx1234";
        let r = scan_secrets(buf, true);
        assert!(r.hits[0].raw.is_some());
    }
}
