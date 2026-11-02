/// Shannon entropy in bits/byte, 0..=8.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let n = data.iter().filter(|&&b| (32..127).contains(&b)).count();
    n as f64 / data.len() as f64
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyIsland {
    pub offset: u64,
    pub size: u64,
    pub h: f64,
    pub kind: &'static str,
}

/// Sliding-window high-entropy islands. Packed/crypto when H > 7.2.
pub fn islands(data: &[u8], window: usize, step: usize) -> Vec<EntropyIsland> {
    let window = window.max(64);
    let step = step.max(32);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + window <= data.len() {
        let slice = &data[i..i + window];
        let h = shannon(slice);
        if h >= 7.2 {
            out.push(EntropyIsland {
                offset: i as u64,
                size: window as u64,
                h,
                kind: "packed_or_crypto",
            });
        }
        i += step;
    }
    merge_islands(out)
}

fn merge_islands(raw: Vec<EntropyIsland>) -> Vec<EntropyIsland> {
    let mut merged: Vec<EntropyIsland> = Vec::new();
    for isl in raw {
        if let Some(last) = merged.last_mut() {
            if isl.offset <= last.offset + last.size {
                let end = (isl.offset + isl.size).max(last.offset + last.size);
                last.size = end - last.offset;
                last.h = last.h.max(isl.h);
                continue;
            }
        }
        merged.push(isl);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert_eq!(shannon(&[0u8; 100]), 0.0);
    }

    #[test]
    fn random_is_high() {
        let mut buf = [0u8; 4096];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(1103515245) + 12345) >> 8) as u8;
        }
        assert!(shannon(&buf) > 7.0);
    }
}
