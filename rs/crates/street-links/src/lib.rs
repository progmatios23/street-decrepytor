//! Auto-identify links. Every hit has confidence + origin. No silent guesses.

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use street_core::{parse_imports, Confidence, Origin};
use street_disasm::{disassemble, DisasmResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub kind: String,
    pub value: String,
    pub offset: u64,
    pub confidence: Confidence,
    pub origin: Origin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkReport {
    pub schema_version: u32,
    pub urls: Vec<Link>,
    pub hosts: Vec<Link>,
    pub paths: Vec<Link>,
    pub imports: Vec<Link>,
    pub xrefs: Vec<Link>,
    pub strings: Vec<Link>,
}

pub fn identify(data: &[u8], image_base: u64, disasm: Option<&DisasmResult>) -> LinkReport {
    let mut urls = Vec::new();
    let mut hosts = Vec::new();
    let mut paths = Vec::new();
    let mut strings = Vec::new();

    let url_re = url_regex();
    for m in url_re.find_iter(data) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            if plausible_url(s) {
                let host = s
                    .split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string();
                urls.push(Link {
                    kind: "url".into(),
                    value: s.trim_end_matches(|c: char| ".,;'\")".contains(c)).into(),
                    offset: m.start() as u64,
                    confidence: Confidence::High,
                    origin: Origin::Signature,
                });
                if !host.is_empty() && host.contains('.') {
                    hosts.push(Link {
                        kind: "host".into(),
                        value: host,
                        offset: m.start() as u64,
                        confidence: Confidence::High,
                        origin: Origin::Signature,
                    });
                }
            }
        }
    }

    // utf-16 URLs
    let mut i = 0usize;
    while i + 16 < data.len() {
        if data[i] == b'h' && data.get(i + 1) == Some(&0) && data.get(i + 2) == Some(&b't') {
            let mut u16s = Vec::new();
            let mut j = i;
            while j + 1 < data.len() && u16s.len() < 160 {
                let w = u16::from_le_bytes([data[j], data[j + 1]]);
                if w == 0 {
                    break;
                }
                if let Some(c) = char::from_u32(w as u32) {
                    if c.is_ascii() {
                        u16s.push(c);
                    } else {
                        break;
                    }
                }
                j += 2;
            }
            let s: String = u16s.into_iter().collect();
            if s.starts_with("http") && plausible_url(&s) {
                urls.push(Link {
                    kind: "url".into(),
                    value: s,
                    offset: i as u64,
                    confidence: Confidence::High,
                    origin: Origin::Signature,
                });
            }
        }
        i += 1;
        if urls.len() > 200 {
            break;
        }
    }

    let ascii = regex::bytes::Regex::new(r"[\x20-\x7e]{8,}").unwrap();
    for m in ascii.find_iter(data).take(4000) {
        let s = String::from_utf8_lossy(m.as_bytes());
        if looks_path(&s) {
            paths.push(Link {
                kind: "path".into(),
                value: s.into_owned(),
                offset: m.start() as u64,
                confidence: Confidence::Medium,
                origin: Origin::Heuristic,
            });
        } else if interesting_string(&s) {
            strings.push(Link {
                kind: "string".into(),
                value: s.into_owned(),
                offset: m.start() as u64,
                confidence: Confidence::Low,
                origin: Origin::Heuristic,
            });
        }
        if paths.len() + strings.len() > 400 {
            break;
        }
    }

    let imports: Vec<Link> = parse_imports(data)
        .into_iter()
        .map(|im| Link {
            kind: "import".into(),
            value: format!("{}!{}", im.dll, im.name),
            offset: im.thunk_rva as u64,
            confidence: Confidence::High,
            origin: Origin::Signature,
        })
        .collect();

    let mut xrefs = Vec::new();
    if let Some(d) = disasm {
        for x in d.xrefs.iter().take(500) {
            xrefs.push(Link {
                kind: x.kind.clone(),
                value: format!("0x{:x}->0x{:x}", x.from, x.to),
                offset: x.from.saturating_sub(image_base),
                confidence: Confidence::High,
                origin: Origin::Decoder,
            });
        }
    } else if data.len() > 0x200 {
        let d = disassemble(
            &data[data.len().min(0x200)..data.len().min(0x200 + 0x8000)],
            image_base + 0x1000,
            street_core::Arch::X64,
            true,
            8000,
        );
        for x in d.xrefs.iter().take(300) {
            xrefs.push(Link {
                kind: x.kind.clone(),
                value: format!("0x{:x}->0x{:x}", x.from, x.to),
                offset: x.from.saturating_sub(image_base),
                confidence: Confidence::Medium,
                origin: Origin::Decoder,
            });
        }
    }

    LinkReport {
        schema_version: 1,
        urls: dedup(urls),
        hosts: dedup(hosts),
        paths: dedup(paths),
        imports,
        xrefs,
        strings: dedup(strings),
    }
}

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https?://(?:localhost|127\.0\.0\.1|[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d{1,5})?(?:/[A-Za-z0-9._~/=?&%#-]*)?").unwrap()
    })
}

fn plausible_url(u: &str) -> bool {
    if !u.contains("://") || u.contains(' ') {
        return false;
    }
    let host = u.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    host.contains('.') || host == "localhost" || host.starts_with("127.")
}

fn looks_path(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 6
        && (t.starts_with("\\\\")
            || (t.len() >= 3 && t.as_bytes()[1] == b':' && t.as_bytes()[2] == b'\\')
            || t.starts_with("/usr/")
            || t.starts_with("/home/"))
}

fn interesting_string(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("http")
        || l.contains("token")
        || l.contains("api")
        || l.contains("license")
        || l.contains("password")
        || l.contains(".dll")
        || l.contains("ntdll")
}

fn dedup(mut v: Vec<Link>) -> Vec<Link> {
    v.sort_by(|a, b| a.value.cmp(&b.value));
    v.dedup_by(|a, b| a.value == b.value && a.kind == b.kind);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_https() {
        let blob = b"xxxxhttps://api.potassium.pro/versionyyyy";
        let r = identify(blob, 0, None);
        assert!(r.urls.iter().any(|u| u.value.contains("api.potassium.pro")), "{:?}", r.urls);
        assert!(r.hosts.iter().any(|h| h.value.contains("potassium.pro")));
    }
}
