//! IR from the IDA-alternative spec. Decoder-backed, confidence on every op.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use street_core::{Confidence, Origin};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrOp {
    Load { dst: String, address: String },
    Store { address: String, value: String },
    Add { dst: String, left: String, right: String },
    Sub { dst: String, left: String, right: String },
    And { dst: String, left: String, right: String },
    Or { dst: String, left: String, right: String },
    Xor { dst: String, left: String, right: String },
    Compare { left: String, right: String },
    Branch { cond: Option<String>, target: u64 },
    Call { target: String },
    Return { value: Option<String> },
    Assign { dst: String, src: String },
    Unknown { asm: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInsn {
    pub addr: u64,
    pub op: IrOp,
    pub confidence: Confidence,
    pub origin: Origin,
    pub asm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub start: u64,
    pub name: String,
    pub ops: Vec<IrInsn>,
}

pub fn lift_x86(code: &[u8], start: u64, bitness: u32, name: &str, max: usize) -> IrFunction {
    let mut decoder = Decoder::with_ip(bitness, code, start, DecoderOptions::NONE);
    let mut ops = Vec::new();
    while decoder.can_decode() && ops.len() < max {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 {
            break;
        }
        ops.push(from_insn(&insn));
        if insn.flow_control() == FlowControl::Return && ops.len() > 1 {
            // keep collecting; functions have multiple rets
        }
    }
    IrFunction {
        start,
        name: name.into(),
        ops,
    }
}

fn from_insn(insn: &Instruction) -> IrInsn {
    let mut fmt = iced_x86::NasmFormatter::new();
    let mut asm = String::new();
    use iced_x86::Formatter;
    fmt.format(insn, &mut asm);
    let m = insn.mnemonic();
    let (op, conf) = match m {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
            if insn.op0_kind() == OpKind::Register && is_mem(insn, 1) {
                (
                    IrOp::Load {
                        dst: r(insn.op0_register()),
                        address: mem(insn),
                    },
                    Confidence::High,
                )
            } else if is_mem(insn, 0) {
                (
                    IrOp::Store {
                        address: mem(insn),
                        value: src(insn, 1),
                    },
                    Confidence::High,
                )
            } else {
                (
                    IrOp::Assign {
                        dst: src(insn, 0),
                        src: src(insn, 1),
                    },
                    Confidence::High,
                )
            }
        }
        Mnemonic::Lea => (
            IrOp::Assign {
                dst: r(insn.op0_register()),
                src: mem(insn),
            },
            Confidence::High,
        ),
        Mnemonic::Add => (binop(insn, |d, l, r| IrOp::Add { dst: d, left: l, right: r }), Confidence::High),
        Mnemonic::Sub => (binop(insn, |d, l, r| IrOp::Sub { dst: d, left: l, right: r }), Confidence::High),
        Mnemonic::And => (binop(insn, |d, l, r| IrOp::And { dst: d, left: l, right: r }), Confidence::High),
        Mnemonic::Or => (binop(insn, |d, l, r| IrOp::Or { dst: d, left: l, right: r }), Confidence::High),
        Mnemonic::Xor => (binop(insn, |d, l, r| IrOp::Xor { dst: d, left: l, right: r }), Confidence::High),
        Mnemonic::Cmp | Mnemonic::Test => (
            IrOp::Compare {
                left: src(insn, 0),
                right: src(insn, 1),
            },
            Confidence::High,
        ),
        Mnemonic::Call => (
            IrOp::Call {
                target: branch_or_indirect(insn),
            },
            Confidence::High,
        ),
        Mnemonic::Ret | Mnemonic::Retf => (IrOp::Return { value: None }, Confidence::High),
        Mnemonic::Jmp => (
            IrOp::Branch {
                cond: None,
                target: near(insn),
            },
            if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
                Confidence::High
            } else {
                Confidence::Low
            },
        ),
        m if is_jcc(m) => (
            IrOp::Branch {
                cond: Some(format!("{m:?}").to_ascii_lowercase()),
                target: near(insn),
            },
            Confidence::High,
        ),
        _ => (IrOp::Unknown { asm: asm.clone() }, Confidence::Low),
    };
    IrInsn {
        addr: insn.ip(),
        op,
        confidence: conf,
        origin: Origin::Decoder,
        asm,
    }
}

fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Js
            | Mnemonic::Jns
    )
}

fn is_mem(insn: &Instruction, op: u32) -> bool {
    insn.op_kind(op) == OpKind::Memory
}

fn r(reg: Register) -> String {
    format!("{reg:?}").to_ascii_lowercase()
}

fn src(insn: &Instruction, op: u32) -> String {
    match insn.op_kind(op) {
        OpKind::Register => r(insn.op_register(op)),
        OpKind::Memory => format!("*({})", mem(insn)),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => format!("0x{:x}", imm(insn, op)),
        _ => "?".into(),
    }
}

fn imm(insn: &Instruction, op: u32) -> u64 {
    match insn.op_kind(op) {
        OpKind::Immediate8 => insn.immediate8() as u64,
        OpKind::Immediate32 => insn.immediate32() as u64,
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        _ => 0,
    }
}

fn mem(insn: &Instruction) -> String {
    let mut s = String::new();
    if insn.memory_base() != Register::None {
        s.push_str(&r(insn.memory_base()));
    }
    if insn.memory_index() != Register::None {
        if !s.is_empty() {
            s.push_str(" + ");
        }
        s.push_str(&r(insn.memory_index()));
        let sc = insn.memory_index_scale();
        if sc > 1 {
            s.push_str(&format!(" * {sc}"));
        }
    }
    let d = insn.memory_displacement64() as i64;
    if d != 0 {
        if s.is_empty() {
            s = format!("0x{d:x}");
        } else if d > 0 {
            s.push_str(&format!(" + 0x{d:x}"));
        } else {
            s.push_str(&format!(" - 0x{:x}", -d));
        }
    }
    if s.is_empty() {
        "0".into()
    } else {
        s
    }
}

fn near(insn: &Instruction) -> u64 {
    if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
        insn.near_branch_target()
    } else {
        0
    }
}

fn branch_or_indirect(insn: &Instruction) -> String {
    if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
        format!("sub_{:x}", insn.near_branch_target())
    } else {
        "indirect".into()
    }
}

fn binop<F: FnOnce(String, String, String) -> IrOp>(insn: &Instruction, f: F) -> IrOp {
    let d = src(insn, 0);
    let rgt = src(insn, 1);
    f(d.clone(), d, rgt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_eax_is_xor_ir() {
        let f = lift_x86(&[0x31, 0xC0, 0xC3], 0x1000, 64, "t", 16);
        assert!(matches!(f.ops[0].op, IrOp::Xor { .. }));
        assert!(matches!(f.ops[1].op, IrOp::Return { .. }));
    }
}
