//! Dword stub invert (Cs2-External class). Real cipher: add/sub/xor/not dword [rcx+disp], imm.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwOp {
    pub op: String,
    pub disp: i32,
    pub imm: u32,
}

impl DwOp {
    pub fn apply(&self, block: &mut [u8]) {
        let off = self.disp as usize;
        if off + 4 > block.len() {
            return;
        }
        let mut v = u32::from_le_bytes(block[off..off + 4].try_into().unwrap());
        match self.op.as_str() {
            "add" => v = v.wrapping_add(self.imm),
            "sub" => v = v.wrapping_sub(self.imm),
            "xor" => v ^= self.imm,
            "not" => v = !v,
            _ => {}
        }
        block[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubLayout {
    pub stub_file_off: usize,
    pub ops: Vec<DwOp>,
    pub key_region_file_off: usize,
    pub block_size: usize,
    pub total_size: usize,
}

pub fn extract_dw_ops(stub: &[u8], stub_rva: u64) -> Vec<DwOp> {
    let mut ops = Vec::new();
    let mut pos = 0usize;
    let mut gap = 0usize;
    while pos + 2 < stub.len() {
        let slice = &stub[pos..];
        let mut decoder = Decoder::with_ip(64, slice, stub_rva + pos as u64, DecoderOptions::NONE);
        if !decoder.can_decode() {
            pos += 1;
            gap += 1;
            continue;
        }
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            pos += 1;
            gap += 1;
            continue;
        }
        if let Some(op) = parse_dw_op(&insn) {
            ops.push(op);
            gap = 0;
        } else {
            gap += insn.len();
            if ops.len() >= 16 && gap > 64 {
                break;
            }
        }
        pos += insn.len();
    }
    ops
}

fn parse_dw_op(insn: &Instruction) -> Option<DwOp> {
    let m = insn.mnemonic();
    let op = match m {
        Mnemonic::Add => "add",
        Mnemonic::Sub => "sub",
        Mnemonic::Xor => "xor",
        Mnemonic::Not => "not",
        _ => return None,
    };
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.memory_base() != Register::RCX && insn.memory_base() != Register::ECX {
        return None;
    }
    if insn.memory_size().size() != 4 {
        return None;
    }
    let disp = insn.memory_displacement64() as i32;
    let imm = if op == "not" {
        0
    } else if insn.op_count() >= 2 {
        match insn.op1_kind() {
            OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                insn.immediate8() as u32
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => insn.immediate32(),
            _ => return None,
        }
    } else {
        0
    };
    Some(DwOp {
        op: op.into(),
        disp,
        imm,
    })
}

pub fn decrypt_region(data: &[u8], layout: &StubLayout) -> Vec<u8> {
    let bs = layout.block_size.max(4);
    let start = layout.key_region_file_off;
    let total = if layout.total_size == 0 {
        data.len().saturating_sub(start)
    } else {
        layout.total_size.min(data.len().saturating_sub(start))
    };
    let src = &data[start..start + total];
    let mut out = Vec::with_capacity(total);
    let mut off = 0usize;
    while off < total {
        let end = (off + bs).min(src.len());
        let mut block = src[off..end].to_vec();
        // pad short final block so disp ops stay in range
        if block.len() < bs {
            block.resize(bs, 0);
        }
        for op in &layout.ops {
            op.apply(&mut block);
        }
        out.extend_from_slice(&block[..end - off]);
        off += bs;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_inverse() {
        let mut b = 0xCAFEBABEu32.to_le_bytes();
        let op = DwOp { op: "xor".into(), disp: 0, imm: 0x0F0F0F0F };
        op.apply(&mut b);
        op.apply(&mut b);
        assert_eq!(u32::from_le_bytes(b), 0xCAFEBABE);
    }

    #[test]
    fn extract_mixed_disp() {
        let mut code = Vec::new();
        code.push(0x50); // push rax
        code.extend_from_slice(&[0x81, 0x41, 0x04]); // add dword [rcx+4], imm
        code.extend_from_slice(&0x11111111u32.to_le_bytes());
        code.extend_from_slice(&[0x81, 0x71, 0x0c]); // xor dword [rcx+0xc], imm
        code.extend_from_slice(&0x22222222u32.to_le_bytes());
        code.extend_from_slice(&[0x81, 0x69, 0x08]); // sub dword [rcx+8], imm
        code.extend_from_slice(&0x33333333u32.to_le_bytes());
        code.extend_from_slice(&[0xF7, 0x11]); // not dword [rcx]
        let ops = extract_dw_ops(&code, 0x1000);
        assert!(ops.len() >= 3, "{ops:?}");
        let disps: Vec<i32> = ops.iter().map(|o| o.disp).collect();
        assert!(disps.contains(&4), "{disps:?}");
        assert!(disps.contains(&8) || disps.contains(&0xc), "{disps:?}");
    }
}
