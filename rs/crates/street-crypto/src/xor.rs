use serde::{Deserialize, Serialize};
use street_core::entropy::shannon;
use street_core::transform::{image_transform, Transform, TransformKind};

/// Magics accepted for *auto* XOR key derivation. Keep this tight — jpeg/pdf/gzip
/// forge too easily from high-entropy PE sections with short keys.
const MAGICS: &[(&[u8], &str)] = &[
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptHit {
    pub kind: &'static str,
    pub cipher: String,
    pub key_hex: String,
    pub magic: String,
    pub score: i32,
    pub transform: Transform,
}

pub fn xor_repeat(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

pub fn decrypt_blob(data: &[u8]) -> Option<DecryptHit> {
    if data.len() < 16 {
        return None;
    }
    // Already plaintext with a real PE — not a decrypt.
    if pe_struct_ok(data) {
        return None;
    }
    // 1-byte key
    for k in 1u8..=255 {
        let pt = xor_repeat(data, &[k]);
        if let Some(m) = magic_of(&pt) {
            if !valid_beyond_key(&pt, m) {
                continue;
            }
            // reject identity / no-op: ct already had same magic
            if data.starts_with(MAGICS.iter().find(|(_, n)| *n == m).map(|(mg, _)| *mg).unwrap_or(&[])) {
                continue;
            }
            return Some(hit("xor1", &[k], m, &pt));
        }
    }
    // 4-byte key anchored on first magic candidate
    for &(mag, name) in MAGICS {
        if data.len() < mag.len() {
            continue;
        }
        if data.starts_with(mag) {
            continue; // already that magic
        }
        let mut key = vec![0u8; mag.len().min(4)];
        if mag.len() >= 2 && mag.len() <= 4 {
            for i in 0..mag.len() {
                key[i] = data[i] ^ mag[i];
            }
            if key.iter().all(|&b| b == 0) {
                continue;
            }
            let pt = xor_repeat(data, &key);
            if pt.starts_with(mag) && valid_beyond_key(&pt, name) {
                return Some(hit("xor_n", &key, name, &pt));
            }
        }
    }
    None
}

fn pe_struct_ok(blob: &[u8]) -> bool {
    if blob.len() < 0x40 || &blob[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes(blob[0x3C..0x40].try_into().unwrap()) as usize;
    e >= 0x40 && e + 4 <= blob.len().min(0x1000) && &blob[e..e + 4] == b"PE\0\0"
}

fn magic_of(pt: &[u8]) -> Option<&'static str> {
    for &(m, n) in MAGICS {
        if pt.starts_with(m) {
            return Some(n);
        }
    }
    None
}

fn valid_beyond_key(pt: &[u8], magic: &str) -> bool {
    match magic {
        "pe" => pe_struct_ok(pt),
        "png" => pt.len() > 16 && &pt[12..16] == b"IHDR",
        "zip" => {
            if pt.len() < 30 || &pt[0..4] != b"PK\x03\x04" {
                return false;
            }
            let ver = u16::from_le_bytes(pt[4..6].try_into().unwrap());
            let method = u16::from_le_bytes(pt[8..10].try_into().unwrap());
            ver <= 90 && matches!(method, 0 | 8 | 9 | 12 | 14 | 98)
        }
        "elf" => {
            pt.len() >= 8
                && pt.starts_with(b"\x7fELF")
                && matches!(pt[4], 1 | 2)
                && matches!(pt[5], 1 | 2)
                && pt[6] == 1
        }
        "pdf" => {
            pt.len() >= 8
                && pt.starts_with(b"%PDF-")
                && matches!(pt[5], b'1' | b'2')
                && pt[6] == b'.'
                && matches!(pt[7], b'0'..=b'7')
        }
        _ => shannon(&pt[..pt.len().min(256)]) < 7.5,
    }
}

fn hit(cipher: &str, key: &[u8], magic: &str, _pt: &[u8]) -> DecryptHit {
    DecryptHit {
        kind: "cipher",
        cipher: cipher.into(),
        key_hex: key.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""),
        magic: magic.into(),
        score: 60,
        transform: image_transform(TransformKind::Cipher, cipher, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_byte_recovers_pe() {
        // Minimal structurally valid PE32+ head, then XOR — must recover as pe not zip.
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // optional magic at e_lfanew+0x18
        let enc: Vec<u8> = pe.iter().map(|b| b ^ 0x5A).collect();
        assert_ne!(&enc[..2], b"MZ");
        let hit = decrypt_blob(&enc).expect("hit");
        assert_eq!(hit.kind, "cipher");
        assert_eq!(hit.magic, "pe", "{hit:?}");
    }
}
