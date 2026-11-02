//! IDA Pro–style string table: EA, length, type, segment, xrefs, escaped C display.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use serde::{Deserialize, Serialize};
use street_core::pe::{parse_pe, rva_to_off, section_bytes};
use street_core::image::LoadedImage;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdaString {
    /// Virtual address (image base + rva)
    pub ea: u64,
    /// File offset
    pub offset: u64,
    pub length: usize,
    /// C = ASCII C-string, UNICODE = UTF-16LE, PASCAL = length-prefixed
    pub encoding: String,
    pub segment: String,
    /// Escaped like IDA: quotes + \n \t \\"
    pub display: String,
    pub raw: String,
    pub xrefs: Vec<u64>,
    pub xref_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdaStringTable {
    pub schema_version: u32,
    pub image_base: u64,
    pub count: usize,
    pub with_xrefs: usize,
    pub strings: Vec<IdaString>,
}

pub fn build_ida_strings(data: &[u8]) -> IdaStringTable {
    let img = match parse_pe(data) {
        Ok(i) => i,
        Err(_) => {
            return IdaStringTable {
                schema_version: 1,
                image_base: 0,
                count: 0,
                with_xrefs: 0,
                strings: vec![],
            };
        }
    };

    let mut by_ea: BTreeMap<u64, IdaString> = BTreeMap::new();

    // --- ASCII C-strings per section ---
    for s in &img.sections {
        let raw = section_bytes(data, s);
        let base_va = img.va(s.va);
        let mut i = 0usize;
        while i < raw.len() {
            if !(32..127).contains(&raw[i]) && raw[i] != 9 && raw[i] != 10 && raw[i] != 13 {
                i += 1;
                continue;
            }
            let start = i;
            while i < raw.len()
                && ((32..127).contains(&raw[i]) || matches!(raw[i], 9 | 10 | 13))
            {
                i += 1;
            }
            let len = i - start;
            // require NUL terminator for true C-string (IDA default)
            let has_nul = i < raw.len() && raw[i] == 0;
            // Executable sections: demand longer / NUL-terminated to avoid opcode noise
            let min_len = if s.executable() { 10 } else { 4 };
            if len >= min_len && (has_nul || len >= 12) {
                let slice = &raw[start..start + len];
                if let Ok(raw_s) = std::str::from_utf8(slice) {
                    if looks_c_string(raw_s) && !(s.executable() && !has_nul) {
                        let ea = base_va + start as u64;
                        let off = s.raw_off as u64 + start as u64;
                        by_ea.entry(ea).or_insert(IdaString {
                            ea,
                            offset: off,
                            length: len + if has_nul { 1 } else { 0 },
                            encoding: "C".into(),
                            segment: s.name.clone(),
                            display: format!("\"{}\"", c_escape(raw_s)),
                            raw: raw_s.to_string(),
                            xrefs: vec![],
                            xref_count: 0,
                        });
                    }
                }
            }
            if has_nul {
                i += 1;
            }
        }
    }

    // --- UTF-16LE ---
    for s in &img.sections {
        let raw = section_bytes(data, s);
        let base_va = img.va(s.va);
        let mut i = 0usize;
        while i + 3 < raw.len() {
            if raw[i] >= 32 && raw[i] < 127 && raw[i + 1] == 0 {
                let start = i;
                let mut bytes = Vec::new();
                while i + 1 < raw.len() {
                    let w = u16::from_le_bytes([raw[i], raw[i + 1]]);
                    if w == 0 {
                        break;
                    }
                    if !(32..127).contains(&(w as u8)) || (w >> 8) != 0 {
                        bytes.clear();
                        break;
                    }
                    bytes.push(w as u8);
                    i += 2;
                }
                if bytes.len() >= 4 {
                    if let Ok(raw_s) = std::str::from_utf8(&bytes) {
                        if looks_c_string(raw_s) {
                            let ea = base_va + start as u64;
                            by_ea.entry(ea).or_insert(IdaString {
                                ea,
                                offset: s.raw_off as u64 + start as u64,
                                length: bytes.len() * 2 + 2,
                                encoding: "UNICODE".into(),
                                segment: s.name.clone(),
                                display: format!("L\"{}\"", c_escape(raw_s)),
                                raw: raw_s.to_string(),
                                xrefs: vec![],
                                xref_count: 0,
                            });
                        }
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    // --- Xrefs from code: lea/mov rip-relative pointing into string EAs ---
    let xrefs = collect_string_xrefs(data, &img, &by_ea);
    for (ea, refs) in xrefs {
        if let Some(s) = by_ea.get_mut(&ea) {
            s.xrefs = refs;
            s.xref_count = s.xrefs.len();
        }
    }

    let mut strings: Vec<_> = by_ea.into_values().collect();
    // IDA-like: sort by address
    strings.sort_by_key(|s| s.ea);
    let with_xrefs = strings.iter().filter(|s| s.xref_count > 0).count();

    IdaStringTable {
        schema_version: 1,
        image_base: img.image_base,
        count: strings.len(),
        with_xrefs,
        strings,
    }
}

pub fn format_ida_listing(table: &IdaStringTable) -> String {
    let mut out = String::new();
    out.push_str("; Street IDA-style strings\n");
    out.push_str("; Format: segment:EA  length  type  xrefs  display\n\n");
    for s in &table.strings {
        let seg = if s.segment.is_empty() { "_unk_" } else { &s.segment };
        let xr = if s.xref_count > 0 {
            format!("XREF:{}", s.xref_count)
        } else {
            "      ".into()
        };
        out.push_str(&format!(
            "{seg}:{ea:016X}  {len:04X}h  {enc:<8}  {xr}  {disp}\n",
            ea = s.ea,
            len = s.length,
            enc = s.encoding,
            disp = s.display,
        ));
        for x in s.xrefs.iter().take(8) {
            out.push_str(&format!("                 CODE XREF: sub_{x:X}\n"));
        }
    }
    out
}

fn collect_string_xrefs(
    data: &[u8],
    img: &LoadedImage,
    strings: &BTreeMap<u64, IdaString>,
) -> BTreeMap<u64, Vec<u64>> {
    let mut map: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let eas: BTreeSet<u64> = strings.keys().copied().collect();
    if eas.is_empty() {
        return BTreeMap::new();
    }

    for s in img.sections.iter().filter(|s| s.executable()) {
        let raw = section_bytes(data, s);
        let va = img.va(s.va);
        let mut off = 0usize;
        let mut n = 0usize;
        while off < raw.len() && n < 200_000 {
            let mut dec = Decoder::with_ip(64, &raw[off..], va + off as u64, DecoderOptions::NONE);
            if !dec.can_decode() {
                off += 1;
                continue;
            }
            let insn = dec.decode();
            if insn.is_invalid() || insn.len() == 0 {
                off += 1;
                continue;
            }
            n += 1;
            off += insn.len();
            if let Some(target) = insn_string_target(&insn) {
                // snap to nearest string start ≤ target within 0x100
                if let Some(&ea) = eas.range(..=target).next_back() {
                    if target.saturating_sub(ea) < 0x100 {
                        map.entry(ea).or_default().insert(insn.ip());
                    }
                }
            }
        }
    }

    map.into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn insn_string_target(insn: &Instruction) -> Option<u64> {
    if insn.is_ip_rel_memory_operand() {
        return Some(insn.ip_rel_memory_address());
    }
    // lea reg, [rip+disp]
    if insn.mnemonic() == Mnemonic::Lea && insn.op1_kind() == OpKind::Memory {
        if insn.is_ip_rel_memory_operand() {
            return Some(insn.ip_rel_memory_address());
        }
    }
    None
}

fn c_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 32 => o.push_str(&format!("\\x{:02x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn looks_c_string(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let alnum = s.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if alnum < 2 {
        return false;
    }
    // reject pure punctuation noise
    let uniq: std::collections::HashSet<char> = s.chars().collect();
    uniq.len() >= 3
}

#[allow(dead_code)]
fn _rva(img: &LoadedImage, data: &[u8], rva: u32) -> Option<usize> {
    rva_to_off(img, rva).map(|x| x as usize).filter(|&o| o < data.len())
}
