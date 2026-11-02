//! Minimal PE32+ builder for tests — not a runnable image.

pub fn minimal_pe64(text: &[u8], sec_name: &str) -> Vec<u8> {
    let mut dos = vec![0u8; 0x80];
    dos[0] = b'M';
    dos[1] = b'Z';
    dos[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let mut pe = Vec::new();
    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine
    pe.extend_from_slice(&1u16.to_le_bytes()); // sections
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0x00F0u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x0022u16.to_le_bytes());

    let mut opt = vec![0u8; 0xF0];
    opt[0..2].copy_from_slice(&0x020Bu16.to_le_bytes());
    opt[16..20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP
    opt[24..32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    opt[56..60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
    opt[60..64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    opt[68..70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
    pe.extend_from_slice(&opt);

    let mut name = [0u8; 8];
    let nb = sec_name.as_bytes();
    name[..nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
    let vsize = text.len() as u32;
    let va = 0x1000u32;
    let rawsize = ((text.len() as u32 + 0x1FF) / 0x200) * 0x200;
    let raw = 0x200u32;
    let chars = 0x6000_0020u32;
    pe.extend_from_slice(&name);
    pe.extend_from_slice(&vsize.to_le_bytes());
    pe.extend_from_slice(&va.to_le_bytes());
    pe.extend_from_slice(&rawsize.to_le_bytes());
    pe.extend_from_slice(&raw.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&chars.to_le_bytes());

    let mut file = dos;
    file.extend_from_slice(&pe);
    if file.len() > raw as usize {
        // headers spilled — pad anyway
    }
    file.resize(raw as usize, 0);
    file.extend_from_slice(text);
    file.resize(raw as usize + rawsize as usize, 0);
    file
}

pub fn pe_with_code(code: &[u8]) -> Vec<u8> {
    let mut body = code.to_vec();
    if body.len() < 64 {
        body.resize(64, 0x90);
    }
    minimal_pe64(&body, ".text")
}
