//! x64 micro-emulator from entry — register/memory trace, no process spawn.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use street_core::pe::{parse_pe, rva_to_off, section_bytes};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmuEvent {
    pub rip: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmuReport {
    pub schema_version: u32,
    pub entry_va: u64,
    pub instructions_run: u64,
    pub stop_reason: String,
    pub regs: BTreeMap<String, String>,
    pub events: Vec<EmuEvent>,
    pub mem_writes: Vec<String>,
    pub calls: Vec<String>,
    pub notes: Vec<String>,
}

struct State {
    regs: [u64; 16],
    rip: u64,
    mem: BTreeMap<u64, u8>,
    writes: Vec<String>,
    calls: Vec<String>,
    events: Vec<EmuEvent>,
}

impl State {
    fn r(&self, reg: Register) -> u64 {
        match reg {
            Register::RAX | Register::EAX => self.regs[0],
            Register::RCX | Register::ECX => self.regs[1],
            Register::RDX | Register::EDX => self.regs[2],
            Register::RBX | Register::EBX => self.regs[3],
            Register::RSP | Register::ESP => self.regs[4],
            Register::RBP | Register::EBP => self.regs[5],
            Register::RSI | Register::ESI => self.regs[6],
            Register::RDI | Register::EDI => self.regs[7],
            Register::R8 | Register::R8D => self.regs[8],
            Register::R9 | Register::R9D => self.regs[9],
            Register::R10 | Register::R10D => self.regs[10],
            Register::R11 | Register::R11D => self.regs[11],
            Register::R12 | Register::R12D => self.regs[12],
            Register::R13 | Register::R13D => self.regs[13],
            Register::R14 | Register::R14D => self.regs[14],
            Register::R15 | Register::R15D => self.regs[15],
            _ => 0,
        }
    }
    fn set_r(&mut self, reg: Register, v: u64) {
        let idx = match reg {
            Register::RAX | Register::EAX => 0,
            Register::RCX | Register::ECX => 1,
            Register::RDX | Register::EDX => 2,
            Register::RBX | Register::EBX => 3,
            Register::RSP | Register::ESP => 4,
            Register::RBP | Register::EBP => 5,
            Register::RSI | Register::ESI => 6,
            Register::RDI | Register::EDI => 7,
            Register::R8 | Register::R8D => 8,
            Register::R9 | Register::R9D => 9,
            Register::R10 | Register::R10D => 10,
            Register::R11 | Register::R11D => 11,
            Register::R12 | Register::R12D => 12,
            Register::R13 | Register::R13D => 13,
            Register::R14 | Register::R14D => 14,
            Register::R15 | Register::R15D => 15,
            _ => return,
        };
        self.regs[idx] = v;
    }
    fn read_u64(&self, addr: u64) -> u64 {
        let mut b = [0u8; 8];
        for i in 0..8 {
            b[i] = self.mem.get(&(addr + i as u64)).copied().unwrap_or(0);
        }
        u64::from_le_bytes(b)
    }
    fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.mem.insert(addr + i as u64, b);
        }
        self.writes.push(format!("{:#x} <- {} bytes", addr, bytes.len()));
    }
}

pub fn emulate_entry(data: &[u8], max_insns: u64) -> EmuReport {
    let mut notes = vec![
        "Micro-emu: iced-x86 step from EP, sparse memory, no OS stubs.".into(),
        "External calls are recorded and skipped (RIP += insn.len).".into(),
    ];
    let Ok(img) = parse_pe(data) else {
        return EmuReport {
            schema_version: 1,
            entry_va: 0,
            instructions_run: 0,
            stop_reason: "pe_parse_gap".into(),
            regs: BTreeMap::new(),
            events: vec![],
            mem_writes: vec![],
            calls: vec![],
            notes: vec!["PE parse failed".into()],
        };
    };
    let entry_va = img.va(img.entry_rva);
    let mut st = State {
        regs: [0; 16],
        rip: entry_va,
        mem: BTreeMap::new(),
        writes: vec![],
        calls: vec![],
        events: vec![],
    };
    // map sections
    for s in &img.sections {
        let raw = section_bytes(data, s);
        let base = img.va(s.va);
        for (i, &b) in raw.iter().enumerate() {
            st.mem.insert(base + i as u64, b);
        }
    }
    // stack
    let stack = 0x0000_7FFF_F000_0000u64;
    st.set_r(Register::RSP, stack);
    st.set_r(Register::RBP, stack);

    let mut ran = 0u64;
    let mut stop = "max_insns".to_string();
    while ran < max_insns {
        let Some(code_off) = va_to_off(&img, data, st.rip) else {
            stop = format!("unmapped_rip_{:#x}", st.rip);
            break;
        };
        let slice = &data[code_off..data.len().min(code_off + 16)];
        let mut dec = Decoder::with_ip(64, slice, st.rip, DecoderOptions::NONE);
        if !dec.can_decode() {
            stop = "decode_fail".into();
            break;
        }
        let insn = dec.decode();
        if insn.is_invalid() || insn.len() == 0 {
            stop = "invalid_insn".into();
            break;
        }
        ran += 1;
        match step(&mut st, &insn) {
            StepResult::Continue => {}
            StepResult::Stop(reason) => {
                stop = reason;
                break;
            }
        }
    }

    let mut regs = BTreeMap::new();
    for (n, r) in [
        ("rax", Register::RAX),
        ("rcx", Register::RCX),
        ("rdx", Register::RDX),
        ("rbx", Register::RBX),
        ("rsp", Register::RSP),
        ("rbp", Register::RBP),
        ("rsi", Register::RSI),
        ("rdi", Register::RDI),
        ("r8", Register::R8),
        ("r9", Register::R9),
        ("rip", Register::None),
    ] {
        if n == "rip" {
            regs.insert("rip".into(), format!("{:#x}", st.rip));
        } else {
            regs.insert(n.into(), format!("{:#x}", st.r(r)));
        }
    }
    notes.push(format!("mapped {} section bytes into sparse mem", st.mem.len()));

    EmuReport {
        schema_version: 1,
        entry_va,
        instructions_run: ran,
        stop_reason: stop,
        regs,
        events: st.events,
        mem_writes: st.writes.into_iter().take(200).collect(),
        calls: st.calls.into_iter().take(100).collect(),
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use street_core::fixture::pe_with_code;

    #[test]
    fn emu_xor_eax_ret() {
        // xor eax,eax ; ret
        let pe = pe_with_code(&[0x31, 0xC0, 0xC3]);
        let r = emulate_entry(&pe, 32);
        assert!(r.instructions_run >= 1, "{r:?}");
        assert_ne!(r.stop_reason, "pe_parse_gap");
    }
}

enum StepResult {
    Continue,
    Stop(String),
}

fn step(st: &mut State, insn: &Instruction) -> StepResult {
    let m = insn.mnemonic();
    let next = st.rip + insn.len() as u64;

    // crypto-ish markers
    if matches!(m, Mnemonic::Xor | Mnemonic::Pxor | Mnemonic::Aesenc | Mnemonic::Aesdec) {
        st.events.push(EmuEvent {
            rip: st.rip,
            kind: "crypto_op".into(),
            detail: format!("{m:?}"),
        });
    }

    match m {
        Mnemonic::Ret | Mnemonic::Retf => {
            let ret = st.read_u64(st.r(Register::RSP));
            st.set_r(Register::RSP, st.r(Register::RSP).wrapping_add(8));
            st.rip = ret;
            if ret == 0 {
                return StepResult::Stop("returned_0".into());
            }
            return StepResult::Continue;
        }
        Mnemonic::Call => {
            let target = if insn.op0_kind() == OpKind::NearBranch64 {
                insn.near_branch_target()
            } else {
                0
            };
            st.calls.push(format!("{:#x} -> {:#x}", st.rip, target));
            st.events.push(EmuEvent {
                rip: st.rip,
                kind: "call".into(),
                detail: format!("{:#x}", target),
            });
            // push return
            let rsp = st.r(Register::RSP).wrapping_sub(8);
            st.set_r(Register::RSP, rsp);
            st.write_bytes(rsp, &next.to_le_bytes());
            if target == 0 || !st.mem.contains_key(&target) {
                // external / IAT — skip
                st.rip = next;
                st.events.push(EmuEvent {
                    rip: st.rip,
                    kind: "external_call_skip".into(),
                    detail: format!("target={target:#x}"),
                });
            } else {
                st.rip = target;
            }
            return StepResult::Continue;
        }
        Mnemonic::Jmp => {
            if insn.op0_kind() == OpKind::NearBranch64 {
                st.rip = insn.near_branch_target();
                return StepResult::Continue;
            }
            st.rip = next;
            return StepResult::Continue;
        }
        Mnemonic::Je
        | Mnemonic::Jne
        | Mnemonic::Ja
        | Mnemonic::Jae
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Jl
        | Mnemonic::Jle => {
            // fall through (no flags yet) — record
            st.events.push(EmuEvent {
                rip: st.rip,
                kind: "jcc_fallthrough".into(),
                detail: format!("{m:?}"),
            });
            st.rip = next;
            return StepResult::Continue;
        }
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd | Mnemonic::Lea => {
            if insn.op0_kind() == OpKind::Register {
                let v = if m == Mnemonic::Lea {
                    mem_addr(st, insn)
                } else {
                    read_op(st, insn, 1)
                };
                st.set_r(insn.op0_register(), v);
            } else if insn.op0_kind() == OpKind::Memory {
                let addr = mem_addr(st, insn);
                let v = read_op(st, insn, 1);
                st.write_bytes(addr, &v.to_le_bytes()[..size_op(insn, 0)]);
            }
        }
        Mnemonic::Xor => {
            if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register
                && insn.op0_register() == insn.op1_register()
            {
                st.set_r(insn.op0_register(), 0);
            } else if insn.op0_kind() == OpKind::Register {
                let a = st.r(insn.op0_register());
                let b = read_op(st, insn, 1);
                st.set_r(insn.op0_register(), a ^ b);
            }
        }
        Mnemonic::Add => {
            if insn.op0_kind() == OpKind::Register {
                let a = st.r(insn.op0_register());
                let b = read_op(st, insn, 1);
                st.set_r(insn.op0_register(), a.wrapping_add(b));
            }
        }
        Mnemonic::Sub => {
            if insn.op0_kind() == OpKind::Register {
                let a = st.r(insn.op0_register());
                let b = read_op(st, insn, 1);
                st.set_r(insn.op0_register(), a.wrapping_sub(b));
            }
        }
        Mnemonic::Push => {
            let v = read_op(st, insn, 0);
            let rsp = st.r(Register::RSP).wrapping_sub(8);
            st.set_r(Register::RSP, rsp);
            st.write_bytes(rsp, &v.to_le_bytes());
        }
        Mnemonic::Pop => {
            if insn.op0_kind() == OpKind::Register {
                let v = st.read_u64(st.r(Register::RSP));
                st.set_r(Register::RSP, st.r(Register::RSP).wrapping_add(8));
                st.set_r(insn.op0_register(), v);
            }
        }
        Mnemonic::Nop | Mnemonic::Endbr64 => {}
        Mnemonic::Int | Mnemonic::Int1 | Mnemonic::Int3 | Mnemonic::Syscall | Mnemonic::Sysenter => {
            st.rip = next;
            return StepResult::Stop(format!("privileged_{m:?}"));
        }
        _ => {
            // unsupported — advance
        }
    }
    st.rip = next;
    StepResult::Continue
}

fn read_op(st: &State, insn: &Instruction, op: u32) -> u64 {
    match insn.op_kind(op) {
        OpKind::Register => st.r(insn.op_register(op)),
        OpKind::Immediate8 => insn.immediate8() as u64,
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32 => insn.immediate32() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Memory => {
            let addr = mem_addr(st, insn);
            st.read_u64(addr)
        }
        _ => 0,
    }
}

fn mem_addr(st: &State, insn: &Instruction) -> u64 {
    let mut a = 0u64;
    if insn.memory_base() != Register::None {
        if insn.is_ip_rel_memory_operand() {
            return insn.ip_rel_memory_address();
        }
        a = a.wrapping_add(st.r(insn.memory_base()));
    }
    if insn.memory_index() != Register::None {
        a = a.wrapping_add(st.r(insn.memory_index()).wrapping_mul(insn.memory_index_scale() as u64));
    }
    a.wrapping_add(insn.memory_displacement64())
}

fn size_op(insn: &Instruction, op: u32) -> usize {
    match insn.op_kind(op) {
        OpKind::Memory => insn.memory_size().size().max(1).min(8),
        _ => 8,
    }
}

fn va_to_off(img: &street_core::image::LoadedImage, data: &[u8], va: u64) -> Option<usize> {
    if va < img.image_base {
        return None;
    }
    let rva = (va - img.image_base) as u32;
    let off = rva_to_off(img, rva)? as usize;
    if off >= data.len() {
        None
    } else {
        Some(off)
    }
}
