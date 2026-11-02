pub mod arm64;
pub mod cfg;
pub mod func;
pub mod x86;

use serde::{Deserialize, Serialize};
use street_core::Arch;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insn {
    pub addr: u64,
    pub size: u8,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub op_str: String,
    pub is_call: bool,
    pub is_jmp: bool,
    pub is_jcc: bool,
    pub is_ret: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmResult {
    pub arch: String,
    pub base: u64,
    pub instructions: Vec<Insn>,
    pub functions: Vec<RecoveredFn>,
    pub xrefs: Vec<Xref>,
    pub cfg_edges: Vec<CfgEdge>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFn {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

pub fn disassemble(
    code: &[u8],
    base: u64,
    arch: Arch,
    recursive: bool,
    max_insns: usize,
) -> DisasmResult {
    match arch {
        Arch::X86 => x86::disassemble(code, base, 32, recursive, max_insns),
        Arch::X64 | Arch::Unknown => x86::disassemble(code, base, 64, recursive, max_insns),
        Arch::Arm64 | Arch::Arm => arm64::disassemble(code, base, recursive, max_insns),
    }
}

pub fn listing(result: &DisasmResult, max: Option<usize>) -> String {
    let mut lines = Vec::new();
    for (i, insn) in result.instructions.iter().enumerate() {
        if let Some(m) = max {
            if i >= m {
                lines.push(format!("; ... truncated at {m}"));
                break;
            }
        }
        lines.push(format!(
            "{:016x}  {:<24}  {:<8} {}",
            insn.addr, insn.bytes_hex, insn.mnemonic, insn.op_str
        ));
    }
    lines.join("\n")
}
