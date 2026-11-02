//! Native motor: machine code → readable C-like pseudocode.
//! Not a commercial VM lifter. Honesty: this is a structured-asm C printer.

pub mod abi;
pub mod cprint;
pub mod ir;
pub mod structure;
pub mod x86_lift;

use serde::{Deserialize, Serialize};
use street_core::Arch;
use street_disasm::func::bitness_of;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Abi {
    Win64,
    Sysv,
    Cdecl,
    Aapcs64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftOptions {
    pub abi: Abi,
    pub asm_comments: bool,
    pub max_insns: usize,
}

impl Default for LiftOptions {
    fn default() -> Self {
        Self {
            abi: Abi::Win64,
            asm_comments: false,
            max_insns: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftResult {
    pub schema_version: u32,
    pub backend: &'static str,
    pub arch: String,
    pub start: u64,
    pub name: String,
    pub signature: String,
    pub c: String,
    pub insn_count: usize,
    pub structured: bool,
    pub notes: Vec<String>,
}

pub fn lift_bytes(code: &[u8], start: u64, arch: Arch, name: &str, opt: &LiftOptions) -> LiftResult {
    match arch {
        Arch::X86 | Arch::X64 | Arch::Unknown => {
            x86_lift::lift(code, start, bitness_of(arch).max(64), name, opt)
        }
        Arch::Arm64 | Arch::Arm => x86_lift::lift_linear_c(code, start, arch, name, opt),
    }
}

pub fn lift_function_from_pe(
    data: &[u8],
    start_va: u64,
    size: usize,
    name: &str,
    opt: &LiftOptions,
) -> Result<LiftResult, String> {
    let img = street_core::pe::parse_pe(data).map_err(|e| e.to_string())?;
    let (bytes, va) = street_disasm::func::function_bytes(data, start_va, size)
        .ok_or_else(|| "function bytes out of image".to_string())?;
    Ok(lift_bytes(bytes, va, img.arch, name, opt))
}
