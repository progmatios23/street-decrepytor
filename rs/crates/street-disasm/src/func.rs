use crate::{disassemble, RecoveredFn};
use street_core::pe::{parse_pe, rva_to_off, section_bytes, text_section};
use street_core::Arch;

pub fn recover_pe(data: &[u8], max_insns: usize) -> Result<(u64, Vec<RecoveredFn>, crate::DisasmResult), String> {
    let img = parse_pe(data).map_err(|e| e.to_string())?;
    let text = text_section(&img).ok_or_else(|| "no .text".to_string())?;
    let bytes = section_bytes(data, text);
    let base = img.va(text.va);
    let mut result = disassemble(bytes, base, img.arch, true, max_insns);
    let entry_va = img.va(img.entry_rva);
    if let Some(f) = result.functions.iter_mut().find(|f| f.start == entry_va) {
        f.name = "entry".into();
    } else {
        result.functions.insert(
            0,
            RecoveredFn {
                start: entry_va,
                end: entry_va + 0x40,
                name: "entry".into(),
                size: 0x40,
            },
        );
    }
    let fns = result.functions.clone();
    Ok((base, fns, result))
}

/// Slice function bytes from a PE image.
pub fn function_bytes(data: &[u8], start_va: u64, size: usize) -> Option<(&[u8], u64)> {
    let img = parse_pe(data).ok()?;
    if start_va < img.image_base {
        return None;
    }
    let rva = (start_va - img.image_base) as u32;
    let off = rva_to_off(&img, rva)? as usize;
    let end = (off + size).min(data.len());
    if off >= data.len() {
        return None;
    }
    Some((&data[off..end], start_va))
}

pub fn bitness_of(arch: Arch) -> u32 {
    match arch {
        Arch::X86 | Arch::Arm => 32,
        _ => 64,
    }
}
