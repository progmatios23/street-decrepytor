//! PE import directory — real IAT / ILT names.

use crate::pe::{parse_pe, rva_to_off};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub thunk_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDll {
    pub dll: String,
    pub count: usize,
    pub funcs: Vec<String>,
}

pub fn parse_imports(data: &[u8]) -> Vec<ImportEntry> {
    let Ok(img) = parse_pe(data) else {
        return vec![];
    };
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let opt = e_lfanew + 0x18;
    let dd = if img.is_64 { opt + 0x70 } else { opt + 0x60 };
    if dd + 16 > data.len() {
        return vec![];
    }
    let imp_rva = u32::from_le_bytes(data[dd + 8..dd + 12].try_into().unwrap());
    if imp_rva == 0 {
        return vec![];
    }
    let mut out = Vec::new();
    let mut desc = match rva_to_off(&img, imp_rva) {
        Some(o) => o as usize,
        None => return out,
    };
    for _ in 0..256 {
        if desc + 20 > data.len() {
            break;
        }
        let oft = u32::from_le_bytes(data[desc..desc + 4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(data[desc + 12..desc + 16].try_into().unwrap());
        let ft = u32::from_le_bytes(data[desc + 16..desc + 20].try_into().unwrap());
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let dll = read_cstr(data, &img, name_rva).unwrap_or_else(|| "unknown.dll".into());
        // Prefer ILT (OriginalFirstThunk); fall back to FT
        let mut thunk = if oft != 0 { oft } else { ft };
        for _ in 0..512 {
            let Some(toff) = rva_to_off(&img, thunk) else { break };
            let toff = toff as usize;
            if img.is_64 {
                if toff + 8 > data.len() {
                    break;
                }
                let val = u64::from_le_bytes(data[toff..toff + 8].try_into().unwrap());
                if val == 0 {
                    break;
                }
                if val & (1u64 << 63) != 0 {
                    out.push(ImportEntry {
                        dll: dll.clone(),
                        name: format!("#{}", val & 0xFFFF),
                        ordinal: Some((val & 0xFFFF) as u16),
                        thunk_rva: thunk,
                    });
                } else {
                    let hint_rva = (val & 0xFFFF_FFFF) as u32;
                    let name = read_cstr(data, &img, hint_rva.wrapping_add(2))
                        .unwrap_or_else(|| format!("rva_{hint_rva:#x}"));
                    out.push(ImportEntry {
                        dll: dll.clone(),
                        name,
                        ordinal: None,
                        thunk_rva: thunk,
                    });
                }
                thunk = thunk.wrapping_add(8);
            } else {
                if toff + 4 > data.len() {
                    break;
                }
                let val = u32::from_le_bytes(data[toff..toff + 4].try_into().unwrap());
                if val == 0 {
                    break;
                }
                if val & 0x8000_0000 != 0 {
                    out.push(ImportEntry {
                        dll: dll.clone(),
                        name: format!("#{}", val & 0xFFFF),
                        ordinal: Some((val & 0xFFFF) as u16),
                        thunk_rva: thunk,
                    });
                } else {
                    let name = read_cstr(data, &img, val.wrapping_add(2))
                        .unwrap_or_else(|| format!("rva_{val:#x}"));
                    out.push(ImportEntry {
                        dll: dll.clone(),
                        name,
                        ordinal: None,
                        thunk_rva: thunk,
                    });
                }
                thunk = thunk.wrapping_add(4);
            }
            if out.len() > 8000 {
                return out;
            }
        }
        desc += 20;
    }
    out
}

pub fn imports_by_dll(data: &[u8]) -> Vec<ImportDll> {
    let mut map: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for e in parse_imports(data) {
        map.entry(e.dll).or_default().push(e.name);
    }
    map.into_iter()
        .map(|(dll, funcs)| ImportDll {
            count: funcs.len(),
            dll,
            funcs,
        })
        .collect()
}

fn read_cstr(data: &[u8], img: &crate::image::LoadedImage, rva: u32) -> Option<String> {
    let off = rva_to_off(img, rva)? as usize;
    if off >= data.len() {
        return None;
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or_else(|| (off + 128).min(data.len()));
    let raw = &data[off..end];
    if raw.is_empty() {
        return None;
    }
    // Import names are ASCII; tolerate latin-1 for broken tables
    let s = String::from_utf8_lossy(raw).into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
