use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown,
}

impl Arch {
    pub fn from_pe_machine(machine: u16) -> Self {
        match machine {
            0x14C => Arch::X86,
            0x8664 => Arch::X64,
            0x1C0 | 0x1C4 => Arch::Arm,
            0xAA64 => Arch::Arm64,
            _ => Arch::Unknown,
        }
    }

    pub fn from_elf_machine(machine: u16) -> Self {
        match machine {
            3 => Arch::X86,
            62 => Arch::X64,
            40 => Arch::Arm,
            183 => Arch::Arm64,
            _ => Arch::Unknown,
        }
    }

    pub fn bitness(self) -> u32 {
        match self {
            Arch::X86 | Arch::Arm => 32,
            Arch::X64 | Arch::Arm64 => 64,
            Arch::Unknown => 0,
        }
    }

    pub fn is_x86_family(self) -> bool {
        matches!(self, Arch::X86 | Arch::X64)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
