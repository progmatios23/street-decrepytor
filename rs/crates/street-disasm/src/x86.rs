use crate::{DisasmResult, Insn, RecoveredFn, Xref};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};

pub fn disassemble(
    code: &[u8],
    base: u64,
    bitness: u32,
    recursive: bool,
    max_insns: usize,
) -> DisasmResult {
    let mut result = DisasmResult {
        arch: if bitness == 64 { "x64".into() } else { "x86".into() },
        base,
        instructions: Vec::new(),
        functions: Vec::new(),
        xrefs: Vec::new(),
        cfg_edges: Vec::new(),
        errors: Vec::new(),
    };
    if code.is_empty() {
        result.errors.push("empty_code".into());
        return result;
    }

    if recursive {
        decode_recursive(code, base, bitness, max_insns, &mut result);
    } else {
        decode_linear(code, base, bitness, max_insns, &mut result);
    }

    recover_functions(&mut result);
    crate::cfg::build_cfg(&mut result);
    result
}

fn decode_linear(code: &[u8], base: u64, bitness: u32, max_insns: usize, out: &mut DisasmResult) {
    let mut off = 0usize;
    while off < code.len() && out.instructions.len() < max_insns {
        let slice = &code[off..];
        let mut decoder = Decoder::with_ip(bitness, slice, base + off as u64, DecoderOptions::NONE);
        if !decoder.can_decode() {
            off += 1;
            continue;
        }
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            off += 1;
            continue;
        }
        out.instructions.push(to_insn(&insn));
        off += insn.len();
    }
}

fn decode_recursive(code: &[u8], base: u64, bitness: u32, max_insns: usize, out: &mut DisasmResult) {
    let end = base + code.len() as u64;
    let mut work: Vec<u64> = vec![base];
    let mut seen = std::collections::HashSet::new();
    while let Some(ip) = work.pop() {
        if out.instructions.len() >= max_insns {
            break;
        }
        if ip < base || ip >= end {
            continue;
        }
        if !seen.insert(ip) {
            continue;
        }
        let off = (ip - base) as usize;
        if off >= code.len() {
            continue;
        }
        let mut decoder = Decoder::with_ip(bitness, &code[off..], ip, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            continue;
        }
        let rec = to_insn(&insn);
        if let Some(t) = rec.target {
            if t >= base && t < end {
                work.push(t);
            }
            let kind = if rec.is_call {
                "call"
            } else if rec.is_jcc {
                "jcc"
            } else {
                "jmp"
            };
            out.xrefs.push(Xref {
                from: rec.addr,
                to: t,
                kind: kind.into(),
            });
        }
        let next = rec.addr + rec.size as u64;
        let flow = insn.flow_control();
        let fallthrough = !matches!(
            flow,
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        );
        out.instructions.push(rec);
        if fallthrough && next < end {
            work.push(next);
        }
    }
    out.instructions.sort_by_key(|i| i.addr);
}

fn to_insn(insn: &Instruction) -> Insn {
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(insn, &mut text);
    let (mnem, op) = split_nasm(&text);
    let flow = insn.flow_control();
    let is_call = matches!(flow, FlowControl::Call | FlowControl::IndirectCall)
        || insn.mnemonic() == Mnemonic::Call;
    let is_ret = matches!(flow, FlowControl::Return) || insn.mnemonic() == Mnemonic::Ret;
    let is_jmp = insn.mnemonic() == Mnemonic::Jmp;
    let is_jcc = matches!(flow, FlowControl::ConditionalBranch) && !is_jmp;
    let target = if is_call || is_jmp || is_jcc {
        if insn.op0_kind() == OpKind::NearBranch64
            || insn.op0_kind() == OpKind::NearBranch32
            || insn.op0_kind() == OpKind::NearBranch16
        {
            Some(insn.near_branch_target())
        } else {
            None
        }
    } else {
        None
    };
    Insn {
        addr: insn.ip(),
        size: insn.len() as u8,
        bytes_hex: String::new(),
        mnemonic: mnem,
        op_str: op,
        is_call,
        is_jmp,
        is_jcc,
        is_ret,
        target,
    }
}

/// Decode a single instruction and fill bytes_hex from the source buffer.
pub fn decode_one(code: &[u8], ip: u64, bitness: u32) -> Option<(Insn, Instruction)> {
    if code.is_empty() {
        return None;
    }
    let mut decoder = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let insn = decoder.decode();
    if insn.is_invalid() || insn.len() == 0 {
        return None;
    }
    let mut rec = to_insn(&insn);
    rec.bytes_hex = hex_encode(&code[..insn.len().min(code.len())]);
    Some((rec, insn))
}

fn split_nasm(text: &str) -> (String, String) {
    let t = text.trim();
    if let Some((a, b)) = t.split_once(' ') {
        (a.to_string(), b.trim().to_string())
    } else {
        (t.to_string(), String::new())
    }
}

fn recover_functions(out: &mut DisasmResult) {
    if out.instructions.is_empty() {
        return;
    }
    let mut starts: Vec<u64> = vec![out.base];
    for x in &out.xrefs {
        if x.kind == "call" {
            starts.push(x.to);
        }
    }
    for insn in &out.instructions {
        // typical prologue
        if insn.mnemonic == "push" && (insn.op_str == "rbp" || insn.op_str == "ebp") {
            starts.push(insn.addr);
        }
    }
    starts.sort_unstable();
    starts.dedup();
    let last = out.instructions.last().map(|i| i.addr + i.size as u64).unwrap_or(out.base);
    for (i, s) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(last);
        out.functions.push(RecoveredFn {
            start: *s,
            end,
            name: format!("sub_{s:x}"),
            size: end.saturating_sub(*s),
        });
    }
}

// hex crate is not a dep of street-disasm — avoid it.
fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

// patch decode_one to use local hex
pub fn fill_bytes(insn: &mut Insn, code_at: &[u8]) {
    let n = insn.size as usize;
    insn.bytes_hex = hex_encode(&code_at[..n.min(code_at.len())]);
}
