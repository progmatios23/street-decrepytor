use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Native,
    Ghidra,
    Ida,
    Binja,
    X64dbg,
}

impl BackendKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "native" | "street" | "lift" => Some(Self::Native),
            "ghidra" | "ghidra-json" => Some(Self::Ghidra),
            "ida" | "hexrays" => Some(Self::Ida),
            "binja" | "binaryninja" | "bn" => Some(Self::Binja),
            "x64dbg" | "x64" => Some(Self::X64dbg),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Ghidra => "ghidra",
            Self::Ida => "ida",
            Self::Binja => "binja",
            Self::X64dbg => "x64dbg",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCaps {
    pub decompile: bool,
    pub asm: bool,
    pub xrefs: bool,
    pub cfg: bool,
    pub pcode: bool,
    pub structs: bool,
    pub strings: bool,
    pub live: bool,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileRequest {
    pub addr: u64,
    pub name: String,
    pub arch: street_core::Arch,
    pub code: Vec<u8>,
    pub abi: street_lift::Abi,
    pub max_chars: usize,
    pub asm_comments: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileText {
    pub schema_version: u32,
    pub backend: String,
    pub addr: u64,
    pub name: String,
    pub signature: String,
    pub c: String,
    pub insn_count: usize,
    pub structured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGap {
    pub kind: String,
    pub site: String,
    pub reason: String,
}

pub trait Decompiler: Send + Sync {
    fn caps(&self) -> BackendCaps;
    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap>;
}

pub fn truncate_c(mut c: String, max: usize) -> (String, bool) {
    if max == 0 || c.len() <= max {
        return (c, false);
    }
    c.truncate(max);
    c.push_str("\n/* truncated; request a smaller window */");
    (c, true)
}
