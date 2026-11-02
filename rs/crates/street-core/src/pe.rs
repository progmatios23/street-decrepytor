use crate::arch::Arch;
use crate::image::{LoadedImage, Section};
use crate::{Result, StreetError};

pub fn parse_pe(data: &[u8]) -> Result<LoadedImage> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(StreetError::Parse("not MZ".into()));
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 0x18 >= data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(StreetError::Parse("mz_no_pe".into()));
    }
    let machine = u16::from_le_bytes(data[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
    let nsec = u16::from_le_bytes(data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    // COFF: SizeOfOptionalHeader at +0x14 (NOT +0x10 — that is NumberOfSymbols)
    let opt_size = u16::from_le_bytes(data[e_lfanew + 0x14..e_lfanew + 0x16].try_into().unwrap()) as usize;
    let opt_magic = u16::from_le_bytes(data[e_lfanew + 0x18..e_lfanew + 0x1A].try_into().unwrap());
    let pe32plus = opt_magic == 0x20B;
    let opt = e_lfanew + 0x18;

    let (entry_rva, image_base, dd_off) = if pe32plus {
        let ep = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().unwrap());
        let ib = if opt + 32 <= data.len() {
            u64::from_le_bytes(data[opt + 24..opt + 32].try_into().unwrap())
        } else {
            0
        };
        (ep, ib, opt + 0x70)
    } else {
        let ep = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().unwrap());
        let ib = u32::from_le_bytes(data[opt + 28..opt + 32].try_into().unwrap()) as u64;
        (ep, ib, opt + 0x60)
    };

    let mut clr_rva = 0u32;
    let mut clr_size = 0u32;
    if dd_off + 15 * 8 <= data.len() {
        let o = dd_off + 14 * 8;
        clr_rva = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        clr_size = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
    }

    let sec_table = e_lfanew + 0x18 + opt_size;
    let mut sections = Vec::with_capacity(nsec.min(96));
    for i in 0..nsec.min(96) {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let name_raw = &data[off..off + 8];
        let name = name_raw
            .split(|b| *b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        let vsize = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        let va = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
        let rsize = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
        let roff = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
        let chars = u32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap());
        sections.push(Section {
            name,
            va,
            vsize,
            raw_off: roff,
            raw_size: rsize,
            chars,
        });
    }

    Ok(LoadedImage {
        arch: Arch::from_pe_machine(machine),
        format: "pe",
        is_64: pe32plus,
        image_base,
        entry_rva,
        sections,
        clr_rva,
        clr_size,
        machine,
        data_len: data.len(),
    })
}

/// Data directory `(rva, size)`. Index matches the PE optional header.
/// PE32+ directories start at optional+0x70, PE32 at optional+0x60.
/// `(image_base, size_of_image)` from the optional header.
pub fn image_span(data: &[u8]) -> Option<(u64, u32)> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let e = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if e + 0x58 >= data.len() || &data[e..e + 4] != b"PE\0\0" {
        return None;
    }
    let opt = e + 0x18;
    let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().ok()?);
    let (base, size_at) = if magic == 0x20B {
        (
            u64::from_le_bytes(data[opt + 24..opt + 32].try_into().ok()?),
            opt + 56,
        )
    } else {
        (
            u32::from_le_bytes(data[opt + 28..opt + 32].try_into().ok()?) as u64,
            opt + 56,
        )
    };
    if size_at + 4 > data.len() {
        return None;
    }
    let size = u32::from_le_bytes(data[size_at..size_at + 4].try_into().ok()?);
    if size == 0 {
        return None;
    }
    Some((base, size))
}

pub fn data_directory(data: &[u8], index: usize) -> Option<(u32, u32)> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let e = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if e + 0x1A > data.len() || &data[e..e + 4] != b"PE\0\0" {
        return None;
    }
    let opt = e + 0x18;
    let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().ok()?);
    let dd = if magic == 0x20B { opt + 0x70 } else { opt + 0x60 };
    let o = dd + index * 8;
    if o + 8 > data.len() {
        return None;
    }
    let rva = u32::from_le_bytes(data[o..o + 4].try_into().ok()?);
    let size = u32::from_le_bytes(data[o + 4..o + 8].try_into().ok()?);
    if rva == 0 || size < 12 {
        return None;
    }
    Some((rva, size))
}

pub fn rva_to_off(img: &LoadedImage, rva: u32) -> Option<u32> {
    for s in &img.sections {
        if rva >= s.va && rva < s.va.saturating_add(s.vsize.max(s.raw_size)) {
            let delta = rva - s.va;
            if delta < s.raw_size {
                return Some(s.raw_off + delta);
            }
        }
    }
    None
}

pub fn section_bytes<'a>(data: &'a [u8], s: &Section) -> &'a [u8] {
    let start = s.raw_off as usize;
    let end = start.saturating_add(s.raw_size as usize).min(data.len());
    if start >= data.len() {
        return &[];
    }
    &data[start..end]
}

pub fn text_section<'a>(img: &'a LoadedImage) -> Option<&'a Section> {
    img.sections
        .iter()
        .find(|s| s.name == ".text" || s.executable())
}

/// File ranges `[start, end)` covered by sections carrying `IMAGE_SCN_MEM_EXECUTE`.
///
/// Opcode-shape scans (e.g. the Cs2-class `dword [rcx+disp]` stub) must run over
/// *code*, not over the whole file. A packed or relocation-heavy host stores most
/// of its bytes in non-executable data, where 2-byte patterns occur at chance rate
/// and rank phantom systems. Empty when the artifact is not a PE — the caller then
/// falls back to the whole blob.
pub fn executable_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let Ok(img) = parse_pe(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in &img.sections {
        if !s.executable() || s.raw_size == 0 {
            continue;
        }
        let start = s.raw_off as usize;
        let end = start.saturating_add(s.raw_size as usize).min(data.len());
        if start < end {
            out.push((start, end));
        }
    }
    out
}

/// True when `off` falls inside one of the executable ranges from
/// [`executable_ranges`]. When `ranges` is empty (non-PE blob) every offset counts.
pub fn in_executable_range(ranges: &[(usize, usize)], off: usize) -> bool {
    ranges.is_empty() || ranges.iter().any(|(s, e)| off >= *s && off < *e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32+ with a `.text` (exec) and a `.reloc` (non-exec) section.
    fn synth_pe(text: &[u8], reloc: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let e = 0x80usize;
        b[e..e + 4].copy_from_slice(b"PE\0\0");
        b[e + 4..e + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        b[e + 6..e + 8].copy_from_slice(&2u16.to_le_bytes());
        b[e + 0x14..e + 0x16].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = e + 0x18;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // sections at e + 0x18 + 0xF0
        let sh = e + 0x18 + 0xF0;
        let text_off = 0x200usize;
        b[sh..sh + 8].copy_from_slice(b".text\0\0\0");
        b[sh + 8..sh + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        b[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh + 16..sh + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
        b[sh + 20..sh + 24].copy_from_slice(&(text_off as u32).to_le_bytes());
        b[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let reloc_off = text_off + text.len();
        let sh2 = sh + 40;
        b[sh2..sh2 + 8].copy_from_slice(b".reloc\0\0");
        b[sh2 + 8..sh2 + 12].copy_from_slice(&(reloc.len() as u32).to_le_bytes());
        b[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sh2 + 16..sh2 + 20].copy_from_slice(&(reloc.len() as u32).to_le_bytes());
        b[sh2 + 20..sh2 + 24].copy_from_slice(&(reloc_off as u32).to_le_bytes());
        b[sh2 + 36..sh2 + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());
        b.resize(reloc_off + reloc.len(), 0);
        b[text_off..text_off + text.len()].copy_from_slice(text);
        b[reloc_off..reloc_off + reloc.len()].copy_from_slice(reloc);
        b
    }

    #[test]
    fn exec_ranges_exclude_data_section() {
        let pe = synth_pe(&[0x90; 16], &[0x81, 0x41, 0x04, 0, 0, 0, 0, 0]);
        let r = executable_ranges(&pe);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].0, 0x200);
        assert!(in_executable_range(&r, 0x200));
        // the .reloc payload sits past .text — must not be reported executable
        assert!(!in_executable_range(&r, 0x200 + 16));
    }
}
