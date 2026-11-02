use crate::arch::Arch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub chars: u32,
}

impl Section {
    pub fn executable(&self) -> bool {
        self.chars & 0x2000_0000 != 0 || self.name == ".text"
    }

    pub fn writable(&self) -> bool {
        self.chars & 0x8000_0000 != 0
    }

    pub fn virtual_only(&self) -> bool {
        self.raw_size == 0 && self.vsize > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedImage {
    pub arch: Arch,
    pub format: &'static str,
    pub is_64: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub sections: Vec<Section>,
    pub clr_rva: u32,
    pub clr_size: u32,
    pub machine: u16,
    pub data_len: usize,
}

impl LoadedImage {
    pub fn virtual_only_count(&self) -> usize {
        self.sections.iter().filter(|s| s.virtual_only()).count()
    }

    pub fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|s| s.name.as_str()).collect()
    }

    pub fn va(&self, rva: u32) -> u64 {
        self.image_base.wrapping_add(rva as u64)
    }
}

pub fn parse_elf_header(data: &[u8]) -> Option<(Arch, bool)> {
    if data.len() < 20 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let class = data[4]; // 1=32, 2=64
    let machine = u16::from_le_bytes(data[18..20].try_into().ok()?);
    Some((Arch::from_elf_machine(machine), class == 2))
}
