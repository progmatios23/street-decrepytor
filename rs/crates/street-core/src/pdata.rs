//! x64 RUNTIME_FUNCTION table from the exception directory.
//!
//! Disk images use the section raw map. A VA-linear observe dump keeps
//! `SizeOfRawData = 0` in the header, so the same RVA is a file offset.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::pe::{data_directory, parse_pe, rva_to_off};

const MAX_FUNCS: usize = 200_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_rva: u32,
    pub begin_va: u64,
    pub end_va: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdataTable {
    pub schema_version: u32,
    pub count: usize,
    pub source: String,
    pub image_base: u64,
    pub dir_rva: u32,
    pub dir_size: u32,
    pub funcs: Vec<RuntimeFunction>,
    pub note: String,
}

pub fn parse_pdata(data: &[u8]) -> PdataTable {
    let img = match parse_pe(data) {
        Ok(i) => i,
        Err(e) => {
            return empty("absent", 0, 0, 0, format!("not a pe: {e}"));
        }
    };
    let Some((rva, size)) = data_directory(data, 3) else {
        return empty(
            "absent",
            img.image_base,
            0,
            0,
            "exception directory empty — <unbekannt, braucht dump>".into(),
        );
    };
    let Some((bytes, source)) = slice_rva(data, &img, rva, size) else {
        return empty(
            "absent",
            img.image_base,
            rva,
            size,
            "exception directory not in the file — virtual until a va-linear dump".into(),
        );
    };
    let mut funcs = Vec::new();
    let n = (bytes.len() / 12).min(MAX_FUNCS);
    for i in 0..n {
        let o = i * 12;
        let begin = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let end = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap());
        let unwind = u32::from_le_bytes(bytes[o + 8..o + 12].try_into().unwrap());
        if begin == 0 || end <= begin {
            continue;
        }
        funcs.push(RuntimeFunction {
            begin_rva: begin,
            end_rva: end,
            unwind_rva: unwind,
            begin_va: img.image_base.wrapping_add(begin as u64),
            end_va: img.image_base.wrapping_add(end as u64),
        });
    }
    let count = funcs.len();
    PdataTable {
        schema_version: 1,
        count,
        source: source.into(),
        image_base: img.image_base,
        dir_rva: rva,
        dir_size: size,
        funcs,
        note: "RUNTIME_FUNCTION from disk or va-linear image. no invented RVA.".into(),
    }
}

pub fn format_pdata(table: &PdataTable) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# FUNCS_PDATA count={} source={} image_base={:#x} dir_rva={:#x} dir_size={}\n",
        table.count, table.source, table.image_base, table.dir_rva, table.dir_size
    ));
    s.push_str(&format!("# {}\n", table.note));
    s.push_str("# begin_va end_va begin_rva end_rva unwind_rva\n");
    for f in &table.funcs {
        s.push_str(&format!(
            "{:#x} {:#x} {:#x} {:#x} {:#x}\n",
            f.begin_va, f.end_va, f.begin_rva, f.end_rva, f.unwind_rva
        ));
    }
    s
}

pub fn write_pdata(data: &[u8], out_dir: &Path) -> Result<PdataTable, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let table = parse_pdata(data);
    std::fs::write(out_dir.join("FUNCS_PDATA.txt"), format_pdata(&table)).map_err(|e| e.to_string())?;
    let meta = PdataTable {
        funcs: Vec::new(),
        ..table.clone()
    };
    std::fs::write(
        out_dir.join("PDATA.json"),
        serde_json::to_vec_pretty(&meta).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    Ok(table)
}

fn empty(source: &str, image_base: u64, dir_rva: u32, dir_size: u32, note: String) -> PdataTable {
    PdataTable {
        schema_version: 1,
        count: 0,
        source: source.into(),
        image_base,
        dir_rva,
        dir_size,
        funcs: Vec::new(),
        note,
    }
}

fn slice_rva<'a>(
    data: &'a [u8],
    img: &crate::image::LoadedImage,
    rva: u32,
    size: u32,
) -> Option<(&'a [u8], &'static str)> {
    let size = (size as usize).min(MAX_FUNCS * 12);
    if let Some(off) = rva_to_off(img, rva) {
        let start = off as usize;
        let end = (start + size).min(data.len());
        if end >= start + 12 {
            return Some((&data[start..end], "raw"));
        }
    }
    let virtual_only = img.sections.iter().any(|sec| {
        rva >= sec.va && rva < sec.va.saturating_add(sec.vsize.max(1)) && sec.raw_size == 0
    });
    if !virtual_only {
        return None;
    }
    // A normal PE is smaller than SizeOfImage. File offset == RVA only when
    // the bytes are a VA-linear dump that actually contains the whole image.
    let linear = crate::pe::image_span(data)
        .map(|(_, size)| size > 0 && data.len() as u64 >= size as u64)
        .unwrap_or(false);
    if !linear {
        return None;
    }
    let start = rva as usize;
    if start >= data.len() {
        return None;
    }
    let end = (start + size).min(data.len());
    if end >= start + 12 {
        Some((&data[start..end], "va_linear"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_runtime_function_from_raw() {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let e = 0x80usize;
        pe[e..e + 4].copy_from_slice(b"PE\0\0");
        pe[e + 4..e + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[e + 6..e + 8].copy_from_slice(&1u16.to_le_bytes());
        pe[e + 0x14..e + 0x16].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = e + 0x18;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        let dd = opt + 0x70 + 3 * 8;
        pe[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        let sh = e + 0x18 + 0xF0;
        pe[sh..sh + 8].copy_from_slice(b".text\0\0\0");
        pe[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let raw = 0x200usize;
        pe[raw..raw + 4].copy_from_slice(&0x1020u32.to_le_bytes());
        pe[raw + 4..raw + 8].copy_from_slice(&0x1080u32.to_le_bytes());
        pe[raw + 8..raw + 12].copy_from_slice(&0x10A0u32.to_le_bytes());
        let t = parse_pdata(&pe);
        assert_eq!(t.source, "raw");
        assert_eq!(t.count, 1);
        assert_eq!(t.funcs[0].begin_va, 0x140001020);
    }

    #[test]
    fn packed_pe_does_not_treat_file_offset_as_rva() {
        let mut pe = vec![0u8; 0x1800];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let e = 0x80usize;
        pe[e..e + 4].copy_from_slice(b"PE\0\0");
        pe[e + 4..e + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[e + 6..e + 8].copy_from_slice(&1u16.to_le_bytes());
        pe[e + 0x14..e + 0x16].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = e + 0x18;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        pe[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        let dd = opt + 0x70 + 3 * 8;
        pe[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        let sh = e + 0x18 + 0xF0;
        pe[sh..sh + 8].copy_from_slice(b".themida");
        pe[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[sh + 16..sh + 20].copy_from_slice(&0u32.to_le_bytes());
        pe[sh + 20..sh + 24].copy_from_slice(&0u32.to_le_bytes());
        pe[0x1000..0x1004].copy_from_slice(&0x1020u32.to_le_bytes());
        pe[0x1004..0x1008].copy_from_slice(&0x1080u32.to_le_bytes());
        let t = parse_pdata(&pe);
        assert_eq!(t.count, 0, "{}", t.note);
        assert_eq!(t.source, "absent");
    }
}
