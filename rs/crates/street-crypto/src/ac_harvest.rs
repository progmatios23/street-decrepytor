//! Harvest anti-cheat / engine / injection surface strings with EA + file offset.

use regex::Regex;
use serde::{Deserialize, Serialize};
use street_core::pe::{parse_pe, rva_to_off};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcHit {
    pub file_offset: u64,
    pub ea: Option<u64>,
    pub segment: Option<String>,
    pub string: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcSurface {
    pub schema_version: u32,
    pub path: String,
    pub image_base: u64,
    pub count: usize,
    pub hits: Vec<AcHit>,
}

fn ac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(hyperion|byfron|anticheat|anti.?cheat|robloxplayer|roblox\.com|CoreGui|ScriptContext|DataModel|TaskScheduler|LuaState|luau_|lua_pcall|VirtualAllocEx|WriteProcessMemory|NtCreateThread|ManualMap|LdrLoadDll|imgui|DXGI|Present|Hook|detour|minhook|umi\.|module\.dll|support\.exe|injector|HttpGet|loadstring|getgenv|getrenv|hookfunction|getrawmetatable|ScriptContext|PushInstance|Luau_Execute)",
        )
        .unwrap()
    })
}

pub fn harvest_ac_surface(path: &str, data: &[u8]) -> AcSurface {
    let img = parse_pe(data).ok();
    let image_base = img.as_ref().map(|i| i.image_base).unwrap_or(0);
    let mut hits = Vec::new();
    let mut cur = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if (32..127).contains(&b) {
            if cur.is_empty() {
                start = i;
            }
            cur.push(b);
        } else {
            if cur.len() >= 5 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    if ac_re().is_match(s) && !noise(s) {
                        let (ea, segment) = resolve(img.as_ref(), data, start);
                        hits.push(AcHit {
                            file_offset: start as u64,
                            ea,
                            segment,
                            string: s.chars().take(200).collect(),
                            tags: tag(s),
                        });
                    }
                }
            }
            cur.clear();
        }
    }
    hits.truncate(800);
    AcSurface {
        schema_version: 1,
        path: path.into(),
        image_base,
        count: hits.len(),
        hits,
    }
}

fn resolve(
    img: Option<&street_core::image::LoadedImage>,
    _data: &[u8],
    file_off: usize,
) -> (Option<u64>, Option<String>) {
    let Some(im) = img else {
        return (None, None);
    };
    for s in &im.sections {
        let start = s.raw_off as usize;
        let end = start + s.raw_size as usize;
        if file_off >= start && file_off < end && s.raw_size > 0 {
            let rva = s.va + (file_off - start) as u32;
            return (Some(im.va(rva)), Some(s.name.clone()));
        }
    }
    let _ = rva_to_off;
    (None, None)
}

fn noise(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    (l.contains("unsupported") || l.contains("not yet supported"))
        && !l.contains("roblox")
        && !l.contains("lua")
        && !l.contains("hyperion")
        && !l.contains("byfron")
}

fn tag(s: &str) -> Vec<String> {
    let l = s.to_ascii_lowercase();
    let mut t = Vec::new();
    for (k, tag) in [
        ("hyperion", "ac"),
        ("byfron", "ac"),
        ("anticheat", "ac"),
        ("roblox.com", "net"),
        ("imgui", "overlay"),
        ("dxgi", "overlay"),
        ("virtualallocex", "inject"),
        ("writeprocessmemory", "inject"),
        ("ntcreatethread", "inject"),
        ("luau_", "lua"),
        ("lua_pcall", "lua"),
        ("scriptcontext", "lua"),
        ("datamodel", "lua"),
        ("loadstring", "exec"),
        ("httpget", "exec"),
        ("hookfunction", "exec"),
    ] {
        if l.contains(k) {
            t.push(tag.into());
        }
    }
    if t.is_empty() {
        t.push("misc".into());
    }
    t.sort();
    t.dedup();
    t
}
