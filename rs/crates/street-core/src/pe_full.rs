//! Full PE weight: every data directory, exports, delay-load, TLS, debug, resources, overlay.

use crate::entropy::shannon;
use crate::pe::{parse_pe, rva_to_off, section_bytes};
use crate::sha256_bytes;
use serde::{Deserialize, Serialize};
use std::path::Path;

const DIR_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "basereloc",
    "debug",
    "architecture",
    "globalptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr",
    "reserved",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDir {
    pub index: u8,
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub ordinal: u16,
    pub name: String,
    pub rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugDir {
    pub type_id: u32,
    pub rva: u32,
    pub size: u32,
    pub pdb_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub start_va: u64,
    pub end_va: u64,
    pub index_va: u64,
    pub callbacks_va: u64,
    pub callbacks: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    pub name: String,
    pub offset: u64,
    pub size: u32,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDump {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub chars: u32,
    pub entropy: f64,
    pub sha256: String,
    pub virtual_only: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFull {
    pub schema_version: u32,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub e_lfanew: u32,
    pub machine: String,
    pub is_64: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub entry_va: u64,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub sections: Vec<SectionDump>,
    pub data_dirs: Vec<DataDir>,
    pub exports: Vec<ExportEntry>,
    pub debug: Vec<DebugDir>,
    pub tls: Option<TlsInfo>,
    pub resources: Vec<ResourceNode>,
    pub overlay_off: u64,
    pub overlay_size: u64,
    pub overlay_sha256: Option<String>,
    pub utf16_strings: Vec<String>,
}

pub fn parse_full(path: &Path, data: &[u8]) -> crate::Result<PeFull> {
    let img = parse_pe(data)?;
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap());
    let e = e_lfanew as usize;
    let opt = e + 0x18;
    let timestamp = u32::from_le_bytes(data[e + 8..e + 12].try_into().unwrap());
    let (subsystem, dll_ch, size_image, size_hdrs, checksum, dd_off) = if img.is_64 {
        (
            u16::from_le_bytes(data[opt + 68..opt + 70].try_into().unwrap_or([0, 0])),
            u16::from_le_bytes(data[opt + 70..opt + 72].try_into().unwrap_or([0, 0])),
            u32::from_le_bytes(data[opt + 56..opt + 60].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(data[opt + 60..opt + 64].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(data[opt + 64..opt + 68].try_into().unwrap_or([0; 4])),
            opt + 0x70,
        )
    } else {
        (
            u16::from_le_bytes(data[opt + 68..opt + 70].try_into().unwrap_or([0, 0])),
            u16::from_le_bytes(data[opt + 70..opt + 72].try_into().unwrap_or([0, 0])),
            u32::from_le_bytes(data[opt + 56..opt + 60].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(data[opt + 60..opt + 64].try_into().unwrap_or([0; 4])),
            u32::from_le_bytes(data[opt + 64..opt + 68].try_into().unwrap_or([0; 4])),
            opt + 0x60,
        )
    };

    let mut data_dirs = Vec::new();
    for i in 0..16 {
        let o = dd_off + i * 8;
        if o + 8 > data.len() {
            break;
        }
        let rva = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let sz = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
        data_dirs.push(DataDir {
            index: i as u8,
            name: DIR_NAMES[i].into(),
            rva,
            size: sz,
        });
    }

    let mut sections = Vec::new();
    for s in &img.sections {
        let raw = section_bytes(data, s);
        sections.push(SectionDump {
            name: s.name.clone(),
            va: s.va,
            vsize: s.vsize,
            raw_off: s.raw_off,
            raw_size: s.raw_size,
            chars: s.chars,
            entropy: shannon(raw),
            sha256: sha256_bytes(raw),
            virtual_only: s.virtual_only(),
            executable: s.executable(),
        });
    }

    let last = img
        .sections
        .iter()
        .map(|s| s.raw_off as u64 + s.raw_size as u64)
        .max()
        .unwrap_or(0);
    let overlay_off = last;
    let overlay_size = (data.len() as u64).saturating_sub(last);
    let overlay_sha256 = if overlay_size > 0 {
        Some(sha256_bytes(&data[last as usize..]))
    } else {
        None
    };

    Ok(PeFull {
        schema_version: 1,
        path: path.display().to_string(),
        size: data.len() as u64,
        sha256: sha256_bytes(data),
        e_lfanew,
        machine: format!("0x{:x}", img.machine),
        is_64: img.is_64,
        image_base: img.image_base,
        entry_rva: img.entry_rva,
        entry_va: img.va(img.entry_rva),
        subsystem,
        dll_characteristics: dll_ch,
        size_of_image: size_image,
        size_of_headers: size_hdrs,
        checksum,
        timestamp,
        exports: parse_exports(data, &img, &data_dirs),
        debug: parse_debug(data, &img, &data_dirs),
        tls: parse_tls(data, &img, &data_dirs),
        resources: parse_resources(data, &img, &data_dirs),
        data_dirs,
        sections,
        overlay_off,
        overlay_size,
        overlay_sha256,
        utf16_strings: extract_utf16(data, 400),
    })
}

pub fn dump_full(path: &Path, out: &Path) -> crate::Result<PeFull> {
    let data = std::fs::read(path)?;
    let full = parse_full(path, &data)?;
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("PE_FULL.json"), serde_json::to_vec_pretty(&full).unwrap())?;

    let sec_dir = out.join("sections");
    std::fs::create_dir_all(&sec_dir)?;
    if let Ok(img) = parse_pe(&data) {
        for s in &img.sections {
            let raw = section_bytes(&data, s);
            let name = if s.name.is_empty() { "unnamed".into() } else { s.name.replace('\0', "") };
            let fname = format!("{:08x}_{}.bin", s.raw_off, sanitize(&name));
            let _ = std::fs::write(sec_dir.join(fname), raw);
        }
    }
    if full.overlay_size > 0 {
        let _ = std::fs::write(out.join("overlay.bin"), &data[full.overlay_off as usize..]);
    }
    let res_dir = out.join("resources");
    std::fs::create_dir_all(&res_dir)?;
    for (i, r) in full.resources.iter().enumerate() {
        let start = r.offset as usize;
        let end = (start + r.size as usize).min(data.len());
        if start < data.len() && end > start {
            let _ = std::fs::write(
                res_dir.join(format!("{:03}_{}_{}.bin", i, sanitize(&r.kind), sanitize(&r.name))),
                &data[start..end],
            );
        }
    }
    // ascii + utf16 dumps
    let mut ascii = String::new();
    let mut cur = Vec::new();
    for &b in &data {
        if (32..127).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 5 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    ascii.push_str(s);
                    ascii.push('\n');
                }
            }
            cur.clear();
        }
    }
    std::fs::write(out.join("STRINGS_ASCII.txt"), ascii)?;
    std::fs::write(out.join("STRINGS_UTF16.txt"), full.utf16_strings.join("\n"))?;
    std::fs::write(out.join("EXPORTS.json"), serde_json::to_vec_pretty(&full.exports).unwrap())?;
    std::fs::write(out.join("DEBUG.json"), serde_json::to_vec_pretty(&full.debug).unwrap())?;
    std::fs::write(out.join("TLS.json"), serde_json::to_vec_pretty(&full.tls).unwrap())?;
    std::fs::write(out.join("DATA_DIRS.json"), serde_json::to_vec_pretty(&full.data_dirs).unwrap())?;
    std::fs::write(
        out.join("IMPORTS.json"),
        serde_json::to_vec_pretty(&crate::imports::imports_by_dll(&data)).unwrap(),
    )?;
    // load config blob if present
    if let Some(d) = full.data_dirs.iter().find(|d| d.name == "load_config" && d.rva != 0) {
        if let Ok(img) = parse_pe(&data) {
            if let Some(off) = rva_to_off(&img, d.rva) {
                let end = (off as usize + d.size as usize).min(data.len());
                let _ = std::fs::write(out.join("LOAD_CONFIG.bin"), &data[off as usize..end]);
            }
        }
    }
    // IAT raw
    if let Some(d) = full.data_dirs.iter().find(|d| d.name == "iat" && d.rva != 0) {
        if let Ok(img) = parse_pe(&data) {
            if let Some(off) = rva_to_off(&img, d.rva) {
                let end = (off as usize + d.size as usize).min(data.len());
                let _ = std::fs::write(out.join("IAT.bin"), &data[off as usize..end]);
            }
        }
    }
    // exception/.pdata raw
    if let Some(d) = full.data_dirs.iter().find(|d| d.name == "exception" && d.rva != 0) {
        if let Ok(img) = parse_pe(&data) {
            if let Some(off) = rva_to_off(&img, d.rva) {
                let end = (off as usize + d.size as usize).min(data.len());
                let _ = std::fs::write(out.join("EXCEPTION_PDATA.bin"), &data[off as usize..end]);
            }
        }
    }
    Ok(full)
}

fn parse_exports(
    data: &[u8],
    img: &crate::image::LoadedImage,
    dirs: &[DataDir],
) -> Vec<ExportEntry> {
    let Some(d) = dirs.iter().find(|d| d.index == 0 && d.rva != 0 && d.size >= 40) else {
        return vec![];
    };
    let Some(off) = rva_to_off(img, d.rva) else {
        return vec![];
    };
    let off = off as usize;
    if off + 40 > data.len() {
        return vec![];
    }
    let ord_base = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
    let n_eat = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap()) as usize;
    let n_names = u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap()) as usize;
    let eat_rva = u32::from_le_bytes(data[off + 28..off + 32].try_into().unwrap());
    let names_rva = u32::from_le_bytes(data[off + 32..off + 36].try_into().unwrap());
    let ords_rva = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap());
    let mut out = Vec::new();
    let Some(names_off) = rva_to_off(img, names_rva).map(|x| x as usize) else {
        return out;
    };
    let Some(ords_off) = rva_to_off(img, ords_rva).map(|x| x as usize) else {
        return out;
    };
    let Some(eat_off) = rva_to_off(img, eat_rva).map(|x| x as usize) else {
        return out;
    };
    for i in 0..n_names.min(4096) {
        let no = names_off + i * 4;
        let oo = ords_off + i * 2;
        if no + 4 > data.len() || oo + 2 > data.len() {
            break;
        }
        let nrva = u32::from_le_bytes(data[no..no + 4].try_into().unwrap());
        let ord = u16::from_le_bytes(data[oo..oo + 2].try_into().unwrap());
        let name = read_cstr(data, img, nrva).unwrap_or_default();
        let eat_i = ord as usize;
        let rva = if eat_i < n_eat && eat_off + eat_i * 4 + 4 <= data.len() {
            u32::from_le_bytes(data[eat_off + eat_i * 4..eat_off + eat_i * 4 + 4].try_into().unwrap())
        } else {
            0
        };
        out.push(ExportEntry {
            ordinal: (ord_base as u16).wrapping_add(ord),
            name,
            rva,
        });
    }
    out
}

fn parse_debug(data: &[u8], img: &crate::image::LoadedImage, dirs: &[DataDir]) -> Vec<DebugDir> {
    let Some(d) = dirs.iter().find(|d| d.index == 6 && d.size >= 28 && d.rva != 0) else {
        return vec![];
    };
    let Some(mut off) = rva_to_off(img, d.rva).map(|x| x as usize) else {
        return vec![];
    };
    let mut out = Vec::new();
    let end = off + d.size as usize;
    while off + 28 <= end.min(data.len()) {
        let type_id = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
        let size = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
        let addr = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
        let mut pdb = None;
        if type_id == 2 {
            // CODEVIEW
            if let Some(po) = rva_to_off(img, addr).map(|x| x as usize) {
                if po + 24 < data.len() && &data[po..po + 4] == b"RSDS" {
                    pdb = read_raw_cstr(&data[po + 24..]);
                }
            }
        }
        out.push(DebugDir {
            type_id,
            rva: addr,
            size,
            pdb_path: pdb,
        });
        off += 28;
    }
    out
}

fn parse_tls(data: &[u8], img: &crate::image::LoadedImage, dirs: &[DataDir]) -> Option<TlsInfo> {
    let d = dirs.iter().find(|d| d.index == 9 && d.rva != 0)?;
    let off = rva_to_off(img, d.rva)? as usize;
    if img.is_64 {
        if off + 40 > data.len() {
            return None;
        }
        let start = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let end = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        let idx = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
        let cb = u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap());
        let mut callbacks = Vec::new();
        if cb >= img.image_base {
            if let Some(co) = rva_to_off(img, (cb - img.image_base) as u32) {
                let mut p = co as usize;
                for _ in 0..32 {
                    if p + 8 > data.len() {
                        break;
                    }
                    let v = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
                    if v == 0 {
                        break;
                    }
                    callbacks.push(v);
                    p += 8;
                }
            }
        }
        Some(TlsInfo {
            start_va: start,
            end_va: end,
            index_va: idx,
            callbacks_va: cb,
            callbacks,
        })
    } else {
        None
    }
}

fn parse_resources(data: &[u8], img: &crate::image::LoadedImage, dirs: &[DataDir]) -> Vec<ResourceNode> {
    let Some(d) = dirs.iter().find(|d| d.index == 2 && d.rva != 0) else {
        return vec![];
    };
    let Some(root) = rva_to_off(img, d.rva).map(|x| x as usize) else {
        return vec![];
    };
    walk_rsrc(data, img, d.rva, root, root, 0, "root")
}

fn walk_rsrc(
    data: &[u8],
    img: &crate::image::LoadedImage,
    res_rva: u32,
    root: usize,
    dir_off: usize,
    depth: u8,
    prefix: &str,
) -> Vec<ResourceNode> {
    let mut out = Vec::new();
    if depth > 4 || dir_off + 16 > data.len() {
        return out;
    }
    let named = u16::from_le_bytes(data[dir_off + 12..dir_off + 14].try_into().unwrap()) as usize;
    let ids = u16::from_le_bytes(data[dir_off + 14..dir_off + 16].try_into().unwrap()) as usize;
    let n = (named + ids).min(64);
    for i in 0..n {
        let e = dir_off + 16 + i * 8;
        if e + 8 > data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes(data[e..e + 4].try_into().unwrap());
        let data_or_dir = u32::from_le_bytes(data[e + 4..e + 8].try_into().unwrap());
        let label = if name_or_id & 0x8000_0000 != 0 {
            format!("{prefix}/str")
        } else {
            format!("{prefix}/id_{}", name_or_id)
        };
        if data_or_dir & 0x8000_0000 != 0 {
            let sub = root + (data_or_dir & 0x7FFF_FFFF) as usize;
            out.extend(walk_rsrc(data, img, res_rva, root, sub, depth + 1, &label));
        } else {
            let leaf = root + data_or_dir as usize;
            if leaf + 16 <= data.len() {
                let rva = u32::from_le_bytes(data[leaf..leaf + 4].try_into().unwrap());
                let sz = u32::from_le_bytes(data[leaf + 4..leaf + 8].try_into().unwrap());
                let file_off = rva_to_off(img, rva).unwrap_or(0) as u64;
                out.push(ResourceNode {
                    name: label,
                    offset: file_off,
                    size: sz,
                    kind: rsrc_type_name(if prefix.contains("id_") {
                        prefix.rsplit('_').next().and_then(|x| x.parse().ok()).unwrap_or(0)
                    } else {
                        0
                    }),
                });
            }
        }
    }
    out
}

fn rsrc_type_name(id: u32) -> String {
    match id {
        1 => "CURSOR".into(),
        2 => "BITMAP".into(),
        3 => "ICON".into(),
        14 => "GROUP_ICON".into(),
        16 => "VERSION".into(),
        24 => "MANIFEST".into(),
        n => format!("type_{n}"),
    }
}

fn extract_utf16(data: &[u8], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 < data.len() && out.len() < limit {
        if data[i] >= 32 && data[i] < 127 && data[i + 1] == 0 {
            let mut j = i;
            let mut buf = Vec::new();
            while j + 1 < data.len() {
                let w = u16::from_le_bytes([data[j], data[j + 1]]);
                if w == 0 {
                    break;
                }
                if w < 32 || w > 126 {
                    buf.clear();
                    break;
                }
                buf.push(w as u8);
                j += 2;
            }
            if buf.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&buf) {
                    out.push(s.to_string());
                }
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn read_cstr(data: &[u8], img: &crate::image::LoadedImage, rva: u32) -> Option<String> {
    let off = rva_to_off(img, rva)? as usize;
    read_raw_cstr(&data[off..])
}

fn read_raw_cstr(data: &[u8]) -> Option<String> {
    let n = data.iter().position(|&b| b == 0).unwrap_or(data.len().min(260));
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&data[..n]).into_owned())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}
