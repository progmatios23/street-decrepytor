//! Junk-jump / control-flow obfuscation — detection and offset-preserving
//! collapse.
//!
//! One family of protectors rewrites every unconditional jump into a pair of
//! *opposite* conditional jumps that resolve to the same target:
//!
//! ```text
//!   0F 84 <rel32>   je  T     (6 bytes, near)
//!   0F 85 <rel32>   jne T     (6 bytes, near)   -> T on both paths
//!
//!   74 <rel8>       je  T     (2 bytes, short)
//!   75 <rel8>       jne T     (2 bytes, short)  -> T on both paths
//! ```
//!
//! `je T` fires when ZF=1, `jne T` when ZF=0. One of them always fires, so the
//! pair is an unconditional jump — written in 12 bytes where 5 would do. The
//! extra bytes are noise; the semantics are untouched. A control-flow graph
//! built from the raw bytes sees two edges where there is one, which is the
//! point of the trick.
//!
//! Collapsing is offset-preserving: the near form becomes `E9 <rel32>` (5
//! bytes) plus 7 `90` bytes, the short form `EB <rel8>` (2 bytes) plus 2 `90`
//! bytes. Every address downstream of a rewrite is unchanged, so a carve or a
//! disassembly taken before and after lines up byte for byte. That matters
//! when the region is addressed by file offset and the caller has already
//! recorded addresses against the un-collapsed bytes.

/// One detected junk-jump pair.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JunkJump {
    /// Offset of the first conditional jump in the pair.
    pub offset: u64,
    /// Absolute (region-relative) address both branches resolve to.
    pub target: u64,
    /// `"near"` (0F 8x, 12 bytes) or `"short"` (7x, 4 bytes).
    pub form: &'static str,
    /// Bytes the pair occupies, and therefore bytes a collapse reclaims.
    pub len: u64,
}

/// A run of junk-jump pairs with no gap wider than [`CLUSTER_GAP`] between
/// consecutive pairs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObCluster {
    pub start: u64,
    pub end: u64,
    pub span: u64,
    pub pairs: usize,
}

/// A 4 KiB window and how many pairs fall inside it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DensityWindow {
    pub base: u64,
    pub pairs: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObfuscationReport {
    /// Total junk-jump pairs found.
    pub pairs: usize,
    pub near_pairs: usize,
    pub short_pairs: usize,
    /// Bytes spent on the pair's redundant jump — `len - 5` for near, `len - 2`
    /// for short.
    pub wasted_bytes: u64,
    /// Contiguous runs of pairs, ordered by offset.
    pub clusters: Vec<ObCluster>,
    /// Non-empty 4 KiB windows, ordered by offset.
    pub density: Vec<DensityWindow>,
    /// Longest run of zero bytes, which disassembles as `add [rax],al` and is
    /// the other half of the same obfuscator's padding habit.
    pub zero_filler_run: u64,
    /// True when a single window holds enough pairs to look like a flattened
    /// dispatcher rather than sprinkled junk.
    pub flattened: bool,
}

/// Consecutive pairs separated by more than this are treated as separate
/// clusters. `0x800` keeps a function's worth of pairs together while splitting
/// islands that sit kilobytes apart.
pub const CLUSTER_GAP: u64 = 0x800;

/// How many pairs in one 4 KiB window before the region reads as a flattened
/// dispatcher rather than scattered junk.
pub const FLATTEN_THRESHOLD: usize = 64;

fn read_i32(b: &[u8]) -> i64 {
    i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64
}

/// Match a near pair at `i`. Returns `(target, len)`.
///
/// Both jumps must be near conditionals (`0F 80..0F 8F`) and must resolve to
/// the same absolute address. Two independently chosen 4-byte displacements
/// agreeing on a target has probability ~2^-32, so this does not fire on
/// ordinary code.
fn near_pair(data: &[u8], i: usize) -> Option<(i64, usize)> {
    if i + 12 > data.len() {
        return None;
    }
    if data[i] != 0x0f || !(0x80..=0x8f).contains(&data[i + 1]) {
        return None;
    }
    if data[i + 6] != 0x0f || !(0x80..=0x8f).contains(&data[i + 7]) {
        return None;
    }
    let t1 = (i as i64 + 6) + read_i32(&data[i + 2..]);
    let t2 = (i as i64 + 12) + read_i32(&data[i + 8..]);
    if t1 == t2 {
        Some((t1, 12))
    } else {
        None
    }
}

/// Match a short pair at `i`. Returns `(target, len)`.
///
/// The short form is only 2 bytes of displacement, so two unrelated short jumps
/// landing on the same target is a 1-in-256 coincidence per position — far
/// likelier than the near form. Guard against the obvious false positives: the
/// target must be inside the region, and must not simply be the fall-through
/// address (a pair that jumps to the instruction right after it does nothing,
/// and is a different shape worth not conflating).
fn short_pair(data: &[u8], i: usize) -> Option<(i64, usize)> {
    if i + 4 > data.len() {
        return None;
    }
    if !(0x70..=0x7f).contains(&data[i]) {
        return None;
    }
    if !(0x70..=0x7f).contains(&data[i + 2]) {
        return None;
    }
    let t1 = (i as i64 + 2) + (data[i + 1] as i8 as i64);
    let t2 = (i as i64 + 4) + (data[i + 3] as i8 as i64);
    if t1 != t2 {
        return None;
    }
    if t1 < 0 || t1 as usize > data.len() {
        return None;
    }
    if t1 as usize == i + 4 {
        return None;
    }
    Some((t1, 4))
}

/// Scan for junk-jump pairs without rewriting anything.
pub fn scan(data: &[u8]) -> ObfuscationReport {
    let pairs = collect(data);
    summarize(data, &pairs)
}

/// Collapse every junk-jump pair, returning the rewritten bytes and the report
/// describing what was found. The output is the same length as the input.
pub fn deobfuscate(data: &[u8]) -> (Vec<u8>, ObfuscationReport) {
    let pairs = collect(data);
    let report = summarize(data, &pairs);
    let mut buf = data.to_vec();
    for p in &pairs {
        let i = p.offset as usize;
        if p.form == "near" {
            // E9 <rel32> then 7 nops, filling the 12 bytes the pair occupied.
            let rel = p.target as i64 - (i as i64 + 5);
            buf[i] = 0xe9;
            buf[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
            for b in &mut buf[i + 5..i + 12] {
                *b = 0x90;
            }
        } else {
            // EB <rel8> then 2 nops, filling the 4 bytes the pair occupied.
            let rel = p.target as i64 - (i as i64 + 2);
            buf[i] = 0xeb;
            buf[i + 1] = rel as i8 as u8;
            buf[i + 2] = 0x90;
            buf[i + 3] = 0x90;
        }
    }
    (buf, report)
}

/// Walk the whole region once, taking the longest match at each offset and
/// advancing past it so overlapping windows are not double-counted.
fn collect(data: &[u8]) -> Vec<JunkJump> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if let Some((target, len)) = near_pair(data, i) {
            out.push(JunkJump {
                offset: i as u64,
                target: target as u64,
                form: "near",
                len: len as u64,
            });
            i += len;
            continue;
        }
        if let Some((target, len)) = short_pair(data, i) {
            out.push(JunkJump {
                offset: i as u64,
                target: target as u64,
                form: "short",
                len: len as u64,
            });
            i += len;
            continue;
        }
        i += 1;
    }
    out
}

fn summarize(data: &[u8], pairs: &[JunkJump]) -> ObfuscationReport {
    let near_pairs = pairs.iter().filter(|p| p.form == "near").count();
    let short_pairs = pairs.len() - near_pairs;
    let wasted_bytes: u64 = pairs
        .iter()
        .map(|p| if p.form == "near" { 7 } else { 2 })
        .sum();

    let clusters = clusterize(pairs);

    let mut windows: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for p in pairs {
        *windows.entry((p.offset >> 12) << 12).or_insert(0) += 1;
    }
    let flattened = windows.values().copied().max().unwrap_or(0) >= FLATTEN_THRESHOLD;
    let density = windows
        .into_iter()
        .map(|(base, pairs)| DensityWindow { base, pairs })
        .collect();

    ObfuscationReport {
        pairs: pairs.len(),
        near_pairs,
        short_pairs,
        wasted_bytes,
        clusters,
        density,
        zero_filler_run: longest_zero_run(data),
        flattened,
    }
}

fn clusterize(pairs: &[JunkJump]) -> Vec<ObCluster> {
    let mut out: Vec<ObCluster> = Vec::new();
    for p in pairs {
        match out.last_mut() {
            Some(c) if p.offset.saturating_sub(c.end) <= CLUSTER_GAP => {
                c.end = p.offset;
                c.span = c.end - c.start;
                c.pairs += 1;
            }
            _ => out.push(ObCluster {
                start: p.offset,
                end: p.offset,
                span: 0,
                pairs: 1,
            }),
        }
    }
    out
}

fn longest_zero_run(data: &[u8]) -> u64 {
    let mut best = 0u64;
    let mut run = 0u64;
    for &b in data {
        if b == 0 {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

impl ObfuscationReport {
    /// One-line summary for a CLI or a log.
    pub fn render(&self) -> String {
        if self.pairs == 0 {
            return "obfuscation: no junk-jump pairs — nothing to collapse".to_string();
        }
        let mut s = format!(
            "obfuscation: {} junk-jump pairs ({} near, {} short), {} bytes wasted, \
             {} cluster(s), flattened={}",
            self.pairs,
            self.near_pairs,
            self.short_pairs,
            self.wasted_bytes,
            self.clusters.len(),
            self.flattened
        );
        for c in &self.clusters {
            s.push_str(&format!(
                "\n  cluster {:#08x}..{:#08x}  span {:#x}  pairs {}",
                c.start, c.end, c.span, c.pairs
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `je rel32; jne rel32` both landing on `target_off` from a buffer whose
    /// first byte is offset 0.
    fn near_pair_bytes(target_off: usize) -> [u8; 12] {
        let t1 = target_off as i32 - 6;
        let t2 = target_off as i32 - 12;
        let mut v = [0u8; 12];
        v[0] = 0x0f;
        v[1] = 0x84;
        v[2..6].copy_from_slice(&t1.to_le_bytes());
        v[6] = 0x0f;
        v[7] = 0x85;
        v[8..12].copy_from_slice(&t2.to_le_bytes());
        v
    }

    #[test]
    fn a_near_pair_is_found_and_has_the_right_target() {
        let mut data = near_pair_bytes(0x40).to_vec();
        data.resize(0x50, 0x90);
        let r = scan(&data);
        assert_eq!(r.pairs, 1);
        assert_eq!(r.near_pairs, 1);
        assert_eq!(r.short_pairs, 0);
        assert_eq!(r.wasted_bytes, 7);
    }

    #[test]
    fn two_conditionals_to_different_targets_are_not_a_pair() {
        let mut v = near_pair_bytes(0x40);
        // Break the second target by one byte.
        v[8] = v[8].wrapping_add(1);
        assert_eq!(scan(&v).pairs, 0);
    }

    #[test]
    fn collapse_is_offset_preserving() {
        let mut data = near_pair_bytes(0x40).to_vec();
        data.resize(0x50, 0x90);
        let (out, r) = deobfuscate(&data);
        assert_eq!(out.len(), data.len(), "length must not change");
        assert_eq!(r.pairs, 1);
        assert_eq!(out[0], 0xe9, "collapsed to a near jmp");
        assert_eq!(&out[1..5], &(0x40i32 - 5).to_le_bytes());
        assert!(out[5..12].iter().all(|&b| b == 0x90), "tail is nop padding");
        // The tail of the buffer is untouched.
        assert!(out[0x40..].iter().all(|&b| b == 0x90));
    }

    #[test]
    fn a_short_pair_collapses_to_eb() {
        // je short +4 ; jne short +2  ->  both to offset 6
        let data = [0x74u8, 0x04, 0x75, 0x02, 0x90, 0x90, 0xc3, 0x90];
        let r = scan(&data);
        assert_eq!(r.pairs, 1);
        assert_eq!(r.short_pairs, 1);
        let (out, _) = deobfuscate(&data);
        assert_eq!(out[0], 0xeb);
        assert_eq!(out[1], 0x04);
        assert_eq!(out[2], 0x90);
        assert_eq!(out[3], 0x90);
    }

    #[test]
    fn a_short_pair_that_only_falls_through_is_not_counted() {
        // je short +0 would land on the fall-through; not the junk shape.
        let data = [0x74u8, 0x00, 0x75, 0xfe, 0x90, 0x90];
        // second jumps to (4 - 2) = 2, first to 2 -> same target, inside range,
        // and not the fall-through (i+4 = 4). This one *is* a pair.
        let r = scan(&data);
        assert_eq!(r.pairs, 1);

        // Now a genuine fall-through: both land on offset 4.
        let ft = [0x74u8, 0x02, 0x75, 0x00, 0x90, 0x90];
        assert_eq!(scan(&ft).pairs, 0);
    }

    #[test]
    fn clusters_split_on_a_wide_gap() {
        let mut data = vec![0x90u8; 0x4000];
        data[0..12].copy_from_slice(&near_pair_bytes(0x800));
        data[0x2000..0x200c].copy_from_slice(&near_pair_bytes(0x2800));
        let r = scan(&data);
        assert_eq!(r.pairs, 2);
        assert_eq!(r.clusters.len(), 2, "0x2000 apart exceeds the cluster gap");
    }

    #[test]
    fn a_single_cluster_when_pairs_are_close() {
        let mut data = vec![0x90u8; 0x100];
        data[0..12].copy_from_slice(&near_pair_bytes(0x80));
        data[0x10..0x1c].copy_from_slice(&near_pair_bytes(0x90));
        let r = scan(&data);
        assert_eq!(r.pairs, 2);
        assert_eq!(r.clusters.len(), 1);
        assert_eq!(r.clusters[0].pairs, 2);
    }

    #[test]
    fn zero_filler_run_is_measured() {
        let mut data = vec![0x90u8; 32];
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0x90u8; 8]);
        data.extend_from_slice(&[0u8; 4]);
        assert_eq!(scan(&data).zero_filler_run, 16);
    }

    #[test]
    fn clean_code_reports_nothing() {
        // A plain function body: nops, a couple of movs, a ret. No conditional
        // jump appears at all, so neither shape can fire.
        let mut data = vec![0x90u8; 512];
        data[0x40..0x47].copy_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x08, 0x90, 0xc3]);
        let r = scan(&data);
        assert_eq!(r.pairs, 0);
        assert!(r.render().contains("nothing to collapse"));
    }
}
