//! Minimal AArch64 decoder for control-flow + linear listing.
//! Full semantic lift lives in street-lift; this recovers B/BL/RET/B.cond.

use crate::{CfgEdge, DisasmResult, Insn, RecoveredFn, Xref};

pub fn disassemble(code: &[u8], base: u64, _recursive: bool, max_insns: usize) -> DisasmResult {
    let mut result = DisasmResult {
        arch: "arm64".into(),
        base,
        instructions: Vec::new(),
        functions: Vec::new(),
        xrefs: Vec::new(),
        cfg_edges: Vec::new(),
        errors: Vec::new(),
    };
    let mut off = 0usize;
    while off + 4 <= code.len() && result.instructions.len() < max_insns {
        let word = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        let addr = base + off as u64;
        let insn = decode_a64(word, addr);
        if let Some(t) = insn.target {
            let kind = if insn.is_call {
                "call"
            } else if insn.is_jcc {
                "jcc"
            } else {
                "jmp"
            };
            result.xrefs.push(Xref {
                from: addr,
                to: t,
                kind: kind.into(),
            });
            result.cfg_edges.push(CfgEdge {
                from: addr,
                to: t,
                kind: kind.into(),
            });
        }
        if !insn.is_jmp && !insn.is_ret {
            result.cfg_edges.push(CfgEdge {
                from: addr,
                to: addr + 4,
                kind: "fall".into(),
            });
        }
        result.instructions.push(insn);
        off += 4;
    }
    if !result.instructions.is_empty() {
        let last = result.instructions.last().unwrap();
        result.functions.push(RecoveredFn {
            start: base,
            end: last.addr + 4,
            name: format!("sub_{base:x}"),
            size: last.addr + 4 - base,
        });
    }
    result
}

fn decode_a64(w: u32, addr: u64) -> Insn {
    let mut mnemonic = "udf";
    let mut op_str = format!("#0x{w:08x}");
    let mut is_call = false;
    let mut is_jmp = false;
    let mut is_jcc = false;
    let mut is_ret = false;
    let mut target = None;

    // B / BL: op0 = 00101, bit 31 = BL
    if (w >> 26) & 0x1F == 0x05 {
        let imm26 = w & 0x03FF_FFFF;
        let simm = ((imm26 as i32) << 6) >> 6; // sign-extend 26
        let dest = addr.wrapping_add(((simm as i64) * 4) as u64);
        target = Some(dest);
        if w & (1 << 31) != 0 {
            mnemonic = "bl";
            is_call = true;
        } else {
            mnemonic = "b";
            is_jmp = true;
        }
        op_str = format!("0x{dest:x}");
    } else if (w >> 24) & 0xFF == 0x54 {
        // B.cond
        let imm19 = (w >> 5) & 0x7FFFF;
        let simm = ((imm19 as i32) << 13) >> 13;
        let dest = addr.wrapping_add(((simm as i64) * 4) as u64);
        let cond = w & 0xF;
        mnemonic = "b.cond";
        is_jcc = true;
        target = Some(dest);
        op_str = format!("0x{dest:x}, cond={cond}");
    } else if w & 0xFFFF_FC1F == 0xD65F_0000 {
        mnemonic = "ret";
        is_ret = true;
        op_str.clear();
    } else if w == 0xD503201F {
        mnemonic = "nop";
        op_str.clear();
    } else if (w >> 24) & 0xFF == 0xD2 || (w >> 24) & 0xFF == 0xF2 {
        mnemonic = "movz";
        op_str = format!("x{}, #0x{:x}", (w >> 5) & 0x1F, (w >> 5) & 0xFFFF); // rough
    } else if (w >> 23) & 0x1FF == 0x1A2 {
        mnemonic = "add";
    } else if (w >> 26) & 0x3F == 0x25 {
        mnemonic = "ldr";
    }

    Insn {
        addr,
        size: 4,
        bytes_hex: format!("{:08x}", w.swap_bytes()),
        mnemonic: mnemonic.into(),
        op_str,
        is_call,
        is_jmp,
        is_jcc,
        is_ret,
        target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ret() {
        let code = 0xD65F03C0u32.to_le_bytes();
        let r = disassemble(&code, 0x1000, false, 16);
        assert_eq!(r.instructions[0].mnemonic, "ret");
        assert!(r.instructions[0].is_ret);
    }

    #[test]
    fn decodes_bl() {
        // BL +4 (imm26=1)
        let w: u32 = (1 << 31) | (0x05 << 26) | 1;
        let r = disassemble(&w.to_le_bytes(), 0x1000, false, 16);
        assert!(r.instructions[0].is_call);
        assert_eq!(r.instructions[0].target, Some(0x1004));
    }
}
