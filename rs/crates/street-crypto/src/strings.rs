//! Automatic string deobfuscation from any PE — entropy + iced-x86, no spawn.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use street_core::pe::{parse_pe, rva_to_off, section_bytes, text_section};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredString {
    pub value: String,
    pub origin: String,
    pub offset: u64,
    pub key_hex: Option<String>,
    pub score: i32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringReport {
    pub schema_version: u32,
    pub plaintext: Vec<RecoveredString>,
    pub deobfuscated: Vec<RecoveredString>,
    pub keys_harvested: Vec<String>,
    pub stats: serde_json::Value,
}

pub fn deobfuscate_strings(data: &[u8]) -> StringReport {
    let mut plaintext = extract_plain(data);
    let mut deob = Vec::new();
    let keys_h;

    let img = parse_pe(data).ok();
    let (code, code_va) = if let Some(ref im) = img {
        if let Some(t) = text_section(im) {
            (section_bytes(data, t).to_vec(), im.va(t.va))
        } else {
            (data[..data.len().min(0x20000)].to_vec(), 0u64)
        }
    } else {
        (data[..data.len().min(0x20000)].to_vec(), 0u64)
    };

    let insns = decode_all(&code, code_va, 80_000);
    let keys = harvest_xor_keys(&insns);
    keys_h = keys.iter().map(|k| hex::encode(k)).take(80).collect();

    deob.extend(stack_strings(&insns));
    deob.extend(ascii_immediates(&insns));
    // lea+xor is high-confidence; bulk section XOR is noisy — keep only strong hits
    deob.extend(emu_xor_loops(&insns, data, img.as_ref()));
    let mut xor_bulk = xor_decode_with_keys(data, &keys, img.as_ref());
    xor_bulk.retain(|s| {
        s.score >= 85
            || s.value.contains("://")
            || s.value.ends_with(".dll")
            || s.value.starts_with(r"Local\")
            || s.value.starts_with('[')
    });
    deob.extend(xor_bulk);

    // quality + dedup
    deob.retain(|s| good_string(&s.value));
    plaintext.retain(|s| good_string(&s.value) && s.value.len() >= 6);
    dedup(&mut deob);
    dedup(&mut plaintext);
    deob.sort_by(|a, b| b.score.cmp(&a.score));
    plaintext.sort_by(|a, b| b.score.cmp(&a.score));

    StringReport {
        schema_version: 1,
        stats: serde_json::json!({
            "plain_n": plaintext.len(),
            "deob_n": deob.len(),
            "keys_n": keys.len(),
            "insns": insns.len(),
        }),
        plaintext: plaintext.into_iter().take(400).collect(),
        deobfuscated: deob.into_iter().take(400).collect(),
        keys_harvested: keys_h,
    }
}

fn decode_all(code: &[u8], va: u64, max: usize) -> Vec<Instruction> {
    let mut v = Vec::new();
    let mut off = 0usize;
    while off < code.len() && v.len() < max {
        let mut d = Decoder::with_ip(64, &code[off..], va + off as u64, DecoderOptions::NONE);
        if !d.can_decode() {
            off += 1;
            continue;
        }
        let i = d.decode();
        if i.is_invalid() || i.len() == 0 {
            off += 1;
            continue;
        }
        off += i.len();
        v.push(i);
    }
    v
}

fn harvest_xor_keys(insns: &[Instruction]) -> Vec<Vec<u8>> {
    use std::collections::BTreeSet;
    let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
    for i in insns {
        if i.mnemonic() != Mnemonic::Xor {
            continue;
        }
        match i.op1_kind() {
            OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                let k = i.immediate8();
                if k != 0 {
                    set.insert(vec![k]);
                }
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => {
                // 4-byte compiler junk is the main FP source — keep only repeating/ascii keys
                let k = i.immediate32().to_le_bytes();
                if k.iter().all(|&b| b == k[0]) && k[0] != 0 {
                    set.insert(vec![k[0]]);
                }
            }
            _ => {}
        }
    }
    set.into_iter().take(64).collect()
}

fn stack_strings(insns: &[Instruction]) -> Vec<RecoveredString> {
    // Collect mov [rbp/rsp+disp], imm8 runs
    let mut runs: Vec<(u64, i64, u8)> = Vec::new();
    for i in insns {
        if !matches!(i.mnemonic(), Mnemonic::Mov) {
            continue;
        }
        if i.op0_kind() != OpKind::Memory || i.memory_size().size() != 1 {
            continue;
        }
        let base = i.memory_base();
        if !matches!(base, Register::RBP | Register::EBP | Register::RSP | Register::ESP) {
            continue;
        }
        let imm = match i.op1_kind() {
            OpKind::Immediate8 => i.immediate8(),
            _ => continue,
        };
        runs.push((i.ip(), i.memory_displacement64() as i64, imm));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < runs.len() {
        let start_ip = runs[i].0;
        let mut bytes: Vec<(i64, u8)> = vec![(runs[i].1, runs[i].2)];
        let mut j = i + 1;
        while j < runs.len() && runs[j].0.saturating_sub(runs[j - 1].0) < 24 {
            bytes.push((runs[j].1, runs[j].2));
            j += 1;
        }
        if bytes.len() >= 4 {
            bytes.sort_by_key(|t| t.0);
            let mut s = Vec::new();
            let mut prev = bytes[0].0;
            for (disp, b) in bytes {
                if disp > prev + 1 {
                    s.push(0);
                }
                s.push(b);
                prev = disp;
            }
            if let Ok(t) = String::from_utf8(s.clone()) {
                if good_string(&t) {
                    out.push(RecoveredString {
                        value: t.trim_end_matches('\0').to_string(),
                        origin: "stack_string".into(),
                        offset: start_ip,
                        key_hex: None,
                        score: 80,
                        evidence: format!("{} byte stores", s.len()),
                    });
                }
            } else {
                let t: String = s.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
                if t.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 4 {
                    out.push(RecoveredString {
                        value: t,
                        origin: "stack_string".into(),
                        offset: start_ip,
                        key_hex: None,
                        score: 55,
                        evidence: "lossy stack".into(),
                    });
                }
            }
        }
        i = j.max(i + 1);
    }
    out
}

fn ascii_immediates(insns: &[Instruction]) -> Vec<RecoveredString> {
    let mut chunks: Vec<(u64, [u8; 4])> = Vec::new();
    for i in insns {
        if i.mnemonic() != Mnemonic::Mov || i.op1_kind() != OpKind::Immediate32 {
            continue;
        }
        let v = i.immediate32().to_le_bytes();
        if v.iter().filter(|&&b| (32..127).contains(&b)).count() >= 3 {
            chunks.push((i.ip(), v));
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < chunks.len() {
        let mut buf = chunks[i].1.to_vec();
        let start = chunks[i].0;
        let mut j = i + 1;
        while j < chunks.len() && chunks[j].0.saturating_sub(chunks[j - 1].0) < 16 {
            buf.extend_from_slice(&chunks[j].1);
            j += 1;
        }
        let t: String = buf
            .iter()
            .map(|&b| if (32..127).contains(&b) { b as char } else { '\0' })
            .collect::<String>()
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string();
        if t.len() >= 4 && good_string(&t) {
            out.push(RecoveredString {
                value: t,
                origin: "imm_ascii".into(),
                offset: start,
                key_hex: None,
                score: 70,
                evidence: "mov r32, imm ascii".into(),
            });
        }
        i = j.max(i + 1);
    }
    out
}

fn xor_decode_with_keys(
    data: &[u8],
    keys: &[Vec<u8>],
    img: Option<&street_core::image::LoadedImage>,
) -> Vec<RecoveredString> {
    let mut out = Vec::new();
    let regions = string_regions(data, img);
    for key in keys.iter().take(24) {
        if key.iter().all(|&b| b == 0) {
            continue;
        }
        for (off, blob) in &regions {
            if blob.len() < 8 {
                continue;
            }
            let pt: Vec<u8> = blob
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()])
                .collect();
            for (s, local) in cstrings(&pt) {
                if key.len() == 1 && key[0] == 0x20 {
                    continue; // case-flip of already-plaintext ASCII
                }
                if !good_string(&s) || s.len() < 8 || !looks_real(&s) {
                    continue;
                }
                out.push(RecoveredString {
                    value: s,
                    origin: "xor_key".into(),
                    offset: off + local as u64,
                    key_hex: Some(hex::encode(key)),
                    score: 75,
                    evidence: format!("xor key={}", hex::encode(key)),
                });
            }
        }
    }
    out
}

/// Walk: lea r, [rip+disp] then nearby xor [r+i], key — recover in place.
fn emu_xor_loops(
    insns: &[Instruction],
    data: &[u8],
    img: Option<&street_core::image::LoadedImage>,
) -> Vec<RecoveredString> {
    let mut out = Vec::new();
    let Some(im) = img else { return out };
    for (n, i) in insns.iter().enumerate() {
        if i.mnemonic() != Mnemonic::Lea || !i.is_ip_rel_memory_operand() {
            continue;
        }
        let target = i.ip_rel_memory_address();
        if target < im.image_base {
            continue;
        }
        let rva = (target - im.image_base) as u32;
        let Some(file_off) = rva_to_off(im, rva) else { continue };
        let file_off = file_off as usize;
        // look ahead 24 insns for xor
        let mut key: Option<u8> = None;
        for k in insns.iter().skip(n + 1).take(24) {
            if k.mnemonic() == Mnemonic::Xor {
                match k.op1_kind() {
                    OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                        key = Some(k.immediate8());
                        break;
                    }
                    _ => {}
                }
            }
        }
        let Some(k) = key else { continue };
        if k == 0 {
            continue;
        }
        let end = (file_off + 256).min(data.len());
        let blob = &data[file_off..end];
        let pt: Vec<u8> = blob.iter().map(|b| b ^ k).collect();
        if let Some((s, _)) = cstrings(&pt).into_iter().next() {
            if good_string(&s) && s.len() >= 5 {
                out.push(RecoveredString {
                    value: s,
                    origin: "lea_xor_loop".into(),
                    offset: file_off as u64,
                    key_hex: Some(format!("{k:02x}")),
                    score: 90,
                    evidence: format!("lea {:#x} xor k={k:#x}", target),
                });
            }
        }
    }
    out
}

fn string_regions(data: &[u8], img: Option<&street_core::image::LoadedImage>) -> Vec<(u64, Vec<u8>)> {
    let mut v = Vec::new();
    if let Some(im) = img {
        for s in &im.sections {
            let b = section_bytes(data, s);
            if b.len() >= 16 {
                v.push((s.raw_off as u64, b.to_vec()));
            }
        }
    } else {
        v.push((0, data[..data.len().min(1 << 20)].to_vec()));
    }
    v
}

fn extract_plain(data: &[u8]) -> Vec<RecoveredString> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut start = 0u64;
    for (i, &b) in data.iter().enumerate() {
        if (32..127).contains(&b) {
            if cur.is_empty() {
                start = i as u64;
            }
            cur.push(b);
        } else {
            if cur.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    out.push(RecoveredString {
                        value: s.to_string(),
                        origin: "plaintext".into(),
                        offset: start,
                        key_hex: None,
                        score: score_plain(s),
                        evidence: "ascii run".into(),
                    });
                }
            }
            cur.clear();
        }
    }
    out
}

fn cstrings(pt: &[u8]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < pt.len() {
        if !(32..127).contains(&pt[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < pt.len() && (32..127).contains(&pt[i]) {
            i += 1;
        }
        if i - start >= 5 {
            if let Ok(s) = std::str::from_utf8(&pt[start..i]) {
                out.push((s.to_string(), start));
            }
        }
        i += 1;
    }
    out
}

fn looks_real(s: &str) -> bool {
    let t = s.trim();
    if t.contains("://") || t.ends_with(".dll") || t.ends_with(".exe") || t.ends_with(".sys") {
        return true;
    }
    if t.starts_with(r"C:\") || t.starts_with(r"Local\") || t.starts_with('[') {
        return true;
    }
    let letters = t.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if letters < 5 {
        return false;
    }
    let vowels = t.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
    vowels * 4 >= letters && t.chars().any(|c| c.is_ascii_lowercase())
}

fn good_string(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 4 || t.len() > 180 {
        return false;
    }
    let alnum = t.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if alnum * 100 / t.len() < 35 && !t.contains("://") && !t.contains('\\') {
        return false;
    }
    let uniq: std::collections::HashSet<char> = t.chars().collect();
    if uniq.len() < 3 {
        return false;
    }
    // reject padding-like
    if t.chars().all(|c| c == ' ' || c == '\t' || c == '.') {
        return false;
    }
    true
}

fn score_plain(s: &str) -> i32 {
    let mut sc = 40;
    let l = s.to_ascii_lowercase();
    if l.contains("http") || l.contains(".dll") || l.contains("error") {
        sc += 25;
    }
    if s.contains('\\') || s.contains('/') {
        sc += 10;
    }
    sc.min(95)
}

fn dedup(v: &mut Vec<RecoveredString>) {
    v.sort_by(|a, b| a.value.cmp(&b.value).then(b.score.cmp(&a.score)));
    v.dedup_by(|a, b| a.value == b.value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_key_recovers_hello() {
        let mut blob = b"~~HelloWorldString~~".to_vec();
        for b in &mut blob {
            *b ^= 0x13;
        }
        // prepend fake so not all ascii
        let keys = vec![vec![0x13]];
        let r = xor_decode_with_keys(&blob, &keys, None);
        assert!(r.iter().any(|s| s.value.contains("Hello")), "{r:?}");
    }
}
