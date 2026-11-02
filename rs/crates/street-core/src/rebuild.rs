//! PE reconstruction from a dumped section set.
//!
//! `dump_full` writes every section out but never the header block. Every field
//! the header carries is recorded in `PE_FULL.json` except a handful of linker
//! defaults — so an image whose original has been lost can be put back
//! together, and the remaining guess space closed against the whole-file hash
//! that was recorded while the original was still on disk.
//!
//! Two entry points:
//!
//! * [`rebuild_from_dump`] — assemble and verify. Always works; the header is
//!   synthesised from the recorded fields plus [`HeaderGuess::default`].
//! * [`crack_header`] — sweep the plausible compiler defaults and stop at the
//!   first guess that reproduces the recorded hash. Turns "a runnable
//!   equivalent" into "the artifact, byte for byte".

use crate::pe_full::PeFull;
use crate::{Result, StreetError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The canonical MSVC DOS stub — 14 bytes of `INT 21h`-era code, the
/// "This program cannot be run in DOS mode" string, then NUL padding. Exactly
/// 64 bytes, which is why `e_lfanew` is `0x80` on every image this linker
/// emits, and why the stub can be reproduced without the original file.
const DOS_STUB: [u8; 64] = [
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_CNT_INIT_DATA: u32 = 0x0000_0040;
const SCN_CNT_UNINIT_DATA: u32 = 0x0000_0080;

/// Linker-default header fields that `parse_full` does not record.
///
/// Everything else in the header is either fixed by the format, derivable from
/// the section table, or already in `PE_FULL.json`. These thirteen are the
/// residue, and the defaults are the VS2019/2022 x64 linker's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderGuess {
    pub linker_major: u8,
    pub linker_minor: u8,
    pub os_major: u16,
    pub os_minor: u16,
    pub image_major: u16,
    pub image_minor: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub characteristics: u16,
}

impl Default for HeaderGuess {
    fn default() -> Self {
        Self {
            linker_major: 14,
            linker_minor: 29,
            os_major: 6,
            os_minor: 0,
            image_major: 0,
            image_minor: 0,
            subsystem_major: 6,
            subsystem_minor: 0,
            stack_reserve: 0x0010_0000,
            stack_commit: 0x0000_1000,
            heap_reserve: 0x0010_0000,
            heap_commit: 0x0000_1000,
            characteristics: 0x22,
        }
    }
}

/// One section's contribution to the rebuilt image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionPlacement {
    pub name: String,
    pub raw_off: u32,
    pub raw_size: u32,
    pub source: String,
    pub bytes_found: u64,
    pub sha256_expected: String,
    pub sha256_actual: String,
    pub match_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildReport {
    pub schema_version: u32,
    pub dump_dir: String,
    pub out_path: String,
    pub guess: HeaderGuess,
    pub size_expected: u64,
    pub size_actual: u64,
    pub size_ok: bool,
    pub sha256_expected: String,
    pub sha256_actual: String,
    pub hash_ok: bool,
    pub sections: Vec<SectionPlacement>,
    pub sections_ok: bool,
    pub header_len: u32,
    pub header_sha256: String,
    /// Fields that were synthesised rather than read back from the dump.
    pub synthesised_fields: Vec<String>,
}

impl RebuildReport {
    /// True when the image is byte-identical to the original, not merely runnable.
    pub fn exact(&self) -> bool {
        self.size_ok && self.sections_ok && self.hash_ok
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("# rebuild-pe\n\n");
        s.push_str(&format!("- dump dir:  `{}`\n", self.dump_dir));
        s.push_str(&format!("- output:    `{}`\n", self.out_path));
        s.push_str(&format!(
            "- size:      {} / {}  {}\n",
            self.size_actual,
            self.size_expected,
            if self.size_ok { "ok" } else { "MISMATCH" }
        ));
        s.push_str(&format!(
            "- sha256:    `{}`\n  expected  `{}`\n  {}  \n",
            self.sha256_actual,
            self.sha256_expected,
            if self.hash_ok {
                "IDENTICAL to the recorded original"
            } else {
                "differs — sections verified, header is a reconstruction"
            }
        ));
        s.push_str(&format!(
            "- sections:  {}  {}\n",
            self.sections.len(),
            if self.sections_ok { "all verified" } else { "MISMATCH" }
        ));
        s.push_str("\n## Section placement\n\n");
        s.push_str("| section | raw_off | raw_size | bytes | sha256 |\n");
        s.push_str("|---|---|---|---|---|\n");
        for p in &self.sections {
            s.push_str(&format!(
                "| `{}` | 0x{:x} | {} | {} | {} |\n",
                p.name,
                p.raw_off,
                p.raw_size,
                p.bytes_found,
                if p.match_ok { "ok" } else { "MISMATCH" }
            ));
        }
        s.push_str("\n## Synthesised header fields\n\n");
        s.push_str("These are not in the dump; they are the linker's defaults and may\n");
        s.push_str("differ from the original. Everything else in the header is either\n");
        s.push_str("fixed by the PE format or derivable from the section table.\n\n");
        for f in &self.synthesised_fields {
            s.push_str(&format!("- {f}\n"));
        }
        s.push_str(&format!(
            "\nheader block: {} bytes, sha256 `{}`\n",
            self.header_len, self.header_sha256
        ));
        s
    }
}

/// Read `PE_FULL.json` from a dump directory.
pub fn load_dump(dir: &Path) -> Result<PeFull> {
    let p = dir.join("PE_FULL.json");
    let raw = std::fs::read(&p)
        .map_err(|e| StreetError::NotFound(format!("{}: {e}", p.display())))?;
    serde_json::from_slice(&raw).map_err(|e| StreetError::Parse(format!("PE_FULL.json: {e}")))
}

/// Locate the dumped bytes for a section. `dump_full` names them
/// `{:08x}_{sanitised-name}.bin`, keyed on the raw offset — which is the one
/// field guaranteed unique across the section table.
fn section_file(dir: &Path, raw_off: u32) -> Option<(std::path::PathBuf, Vec<u8>)> {
    let want = format!("{:08x}_", raw_off);
    let rd = std::fs::read_dir(dir.join("sections")).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(&want) && name.ends_with(".bin") {
            if let Ok(bytes) = std::fs::read(e.path()) {
                return Some((e.path(), bytes));
            }
        }
    }
    None
}

/// Header offsets, for the fields that are fixed by the format.
mod off {
    pub const DOS_STUB: usize = 0x40;
    pub const PE_SIG: usize = 0x80;
    pub const COFF: usize = 0x84;
    pub const OPT: usize = 0x98;
    pub const SEC_ENTRY: usize = 40;
}

fn put_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Synthesise the header block: `size_of_headers` bytes, section table filled
/// from the dump, everything else from the format and the guess.
pub fn synthesize_header(full: &PeFull, g: &HeaderGuess) -> Result<Vec<u8>> {
    let len = full.size_of_headers as usize;
    let opt_size: u16 = if full.is_64 { 240 } else { 224 };
    // The section table starts right after the optional header, whose length is
    // not fixed — 240 bytes for PE32+, 224 for PE32.
    let sec_table = off::OPT + opt_size as usize;
    let need = sec_table + off::SEC_ENTRY * full.sections.len();
    if len < need {
        return Err(StreetError::Parse(format!(
            "size_of_headers {len} cannot hold {} section headers (needs {need})",
            full.sections.len()
        )));
    }
    if full.e_lfanew as usize != off::PE_SIG {
        return Err(StreetError::Parse(format!(
            "e_lfanew is 0x{:x}, not 0x80 — this rebuilder only knows the \
             linker's canonical stub layout",
            full.e_lfanew
        )));
    }
    if full.sections.len() > u16::MAX as usize {
        return Err(StreetError::Parse("too many sections".into()));
    }

    let mut b = vec![0u8; len];

    // ── DOS header ──────────────────────────────────────────────────────────
    b[0] = b'M';
    b[1] = b'Z';
    put_u16(&mut b, 0x02, 0x0090); // e_cblp
    put_u16(&mut b, 0x04, 0x0003); // e_cp
    put_u16(&mut b, 0x08, 0x0004); // e_cparhdr
    put_u16(&mut b, 0x0C, 0xFFFF); // e_maxalloc
    put_u16(&mut b, 0x10, 0x00B8); // e_sp
    put_u16(&mut b, 0x18, 0x0040); // e_lfarlc
    put_u32(&mut b, 0x3C, full.e_lfanew);

    // ── DOS stub ────────────────────────────────────────────────────────────
    b[off::DOS_STUB..off::DOS_STUB + DOS_STUB.len()].copy_from_slice(&DOS_STUB);

    // ── PE signature + COFF header ──────────────────────────────────────────
    b[off::PE_SIG..off::PE_SIG + 4].copy_from_slice(b"PE\0\0");
    let coff = off::COFF;
    let machine = u16::from_str_radix(full.machine.trim_start_matches("0x"), 16)
        .map_err(|_| StreetError::Parse(format!("bad machine {:?}", full.machine)))?;
    put_u16(&mut b, coff, machine);
    put_u16(&mut b, coff + 2, full.sections.len() as u16);
    put_u32(&mut b, coff + 4, full.timestamp);
    // PointerToSymbolTable / NumberOfSymbols stay zero — no COFF symbol table.
    // SizeOfOptionalHeader sits at COFF+0x10; COFF+0x14 is NumberOfSymbols.
    put_u16(&mut b, coff + 0x10, opt_size);
    put_u16(&mut b, coff + 0x12, g.characteristics);

    // ── Optional header ─────────────────────────────────────────────────────
    let o = off::OPT;
    put_u16(&mut b, o, if full.is_64 { 0x20B } else { 0x10B });
    b[o + 2] = g.linker_major;
    b[o + 3] = g.linker_minor;

    let mut code = 0u32;
    let mut init = 0u32;
    let mut uninit = 0u32;
    let mut base_of_code = 0u32;
    for s in &full.sections {
        if s.chars & SCN_CNT_CODE != 0 {
            code = code.saturating_add(s.raw_size);
            if base_of_code == 0 {
                base_of_code = s.va;
            }
        }
        if s.chars & SCN_CNT_INIT_DATA != 0 {
            init = init.saturating_add(s.raw_size);
        }
        if s.chars & SCN_CNT_UNINIT_DATA != 0 {
            uninit = uninit.saturating_add(s.raw_size);
        }
    }
    put_u32(&mut b, o + 4, code); // SizeOfCode
    put_u32(&mut b, o + 8, init); // SizeOfInitializedData
    put_u32(&mut b, o + 12, uninit); // SizeOfUninitializedData
    put_u32(&mut b, o + 16, full.entry_rva);
    put_u32(&mut b, o + 20, base_of_code);

    let (sect_align, file_align) = alignment(full)?;
    if full.is_64 {
        put_u64(&mut b, o + 24, full.image_base);
        put_u32(&mut b, o + 32, sect_align);
        put_u32(&mut b, o + 36, file_align);
    } else {
        put_u32(&mut b, o + 28, full.image_base as u32);
        put_u32(&mut b, o + 32, sect_align);
        put_u32(&mut b, o + 36, file_align);
    }
    put_u16(&mut b, o + 40, g.os_major);
    put_u16(&mut b, o + 42, g.os_minor);
    put_u16(&mut b, o + 44, g.image_major);
    put_u16(&mut b, o + 46, g.image_minor);
    put_u16(&mut b, o + 48, g.subsystem_major);
    put_u16(&mut b, o + 50, g.subsystem_minor);
    put_u32(&mut b, o + 52, 0); // Win32VersionValue
    put_u32(&mut b, o + 56, full.size_of_image);
    put_u32(&mut b, o + 60, full.size_of_headers);
    put_u32(&mut b, o + 64, full.checksum);
    put_u16(&mut b, o + 68, full.subsystem);
    put_u16(&mut b, o + 70, full.dll_characteristics);
    let (so, sd) = if full.is_64 { (72usize, 8usize) } else { (72, 4) };
    if full.is_64 {
        put_u64(&mut b, o + so, g.stack_reserve);
        put_u64(&mut b, o + so + sd, g.stack_commit);
        put_u64(&mut b, o + so + sd * 2, g.heap_reserve);
        put_u64(&mut b, o + so + sd * 3, g.heap_commit);
    } else {
        put_u32(&mut b, o + so, g.stack_reserve as u32);
        put_u32(&mut b, o + so + sd, g.stack_commit as u32);
        put_u32(&mut b, o + so + sd * 2, g.heap_reserve as u32);
        put_u32(&mut b, o + so + sd * 3, g.heap_commit as u32);
    }
    let dd_off = if full.is_64 { o + 0x70 } else { o + 0x60 };
    put_u32(&mut b, dd_off - 8, 0); // LoaderFlags
    put_u32(&mut b, dd_off - 4, 16); // NumberOfRvaAndSizes

    for d in &full.data_dirs {
        let e = dd_off + d.index as usize * 8;
        if e + 8 > b.len() {
            break;
        }
        put_u32(&mut b, e, d.rva);
        put_u32(&mut b, e + 4, d.size);
    }

    // ── Section table ───────────────────────────────────────────────────────
    for (i, s) in full.sections.iter().enumerate() {
        let e = sec_table + i * off::SEC_ENTRY;
        let raw = s.name.as_bytes();
        let n = raw.len().min(8);
        b[e..e + n].copy_from_slice(&raw[..n]);
        put_u32(&mut b, e + 8, s.vsize);
        put_u32(&mut b, e + 12, s.va);
        put_u32(&mut b, e + 16, s.raw_size);
        put_u32(&mut b, e + 20, s.raw_off);
        // PointerToRelocations / Linenumbers and their counts stay zero.
        put_u32(&mut b, e + 36, s.chars);
    }

    Ok(b)
}

/// Recover the alignment pair the image was linked with. Both are observable:
/// every section RVA is section-aligned and every raw offset is file-aligned.
fn alignment(full: &PeFull) -> Result<(u32, u32)> {
    let sect = full
        .sections
        .iter()
        .map(|s| s.va)
        .filter(|v| *v != 0)
        .fold(u32::MAX, |a, b| a.min(b));
    let file = full
        .sections
        .iter()
        .map(|s| s.raw_off)
        .filter(|v| *v != 0)
        .fold(u32::MAX, |a, b| a.min(b));
    let sect_align = if sect == u32::MAX { 0x1000 } else { sect };
    let file_align = if file == u32::MAX { 0x200 } else { file };
    if !sect_align.is_power_of_two() || !file_align.is_power_of_two() {
        return Err(StreetError::Parse(format!(
            "derived alignment is not a power of two: section=0x{sect_align:x} file=0x{file_align:x}"
        )));
    }
    Ok((sect_align, file_align))
}

/// The image with its header block removed — the part the guess cannot affect.
fn assemble_tail(dir: &Path, full: &PeFull) -> Result<(Vec<u8>, Vec<SectionPlacement>)> {
    let hdr_len = full.size_of_headers as u64;
    let total = full.size;
    if total < hdr_len {
        return Err(StreetError::Parse("size < size_of_headers".into()));
    }
    let mut tail = vec![0u8; (total - hdr_len) as usize];
    let mut placements = Vec::with_capacity(full.sections.len());

    for s in &full.sections {
        let mut bytes_found = 0u64;
        let mut source = String::from("(virtual only — nothing on disk)");
        // A disk-empty section has no bytes to verify; `dump_full` recorded the
        // empty-string hash for it, so echoing that back keeps the comparison
        // honest without inventing a pass.
        let mut actual = s.sha256.clone();

        if s.raw_size > 0 {
            match section_file(dir, s.raw_off) {
                Some((path, bytes)) => {
                    source = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    bytes_found = bytes.len() as u64;
                    actual = crate::sha256_bytes(&bytes);
                    let start = (s.raw_off as u64).saturating_sub(hdr_len) as usize;
                    let n = bytes.len().min(s.raw_size as usize);
                    if start + n <= tail.len() {
                        tail[start..start + n].copy_from_slice(&bytes[..n]);
                    }
                }
                None => {
                    source = String::from("MISSING from dump");
                    actual = crate::sha256_bytes(&[]);
                }
            }
        }

        placements.push(SectionPlacement {
            name: s.name.clone(),
            raw_off: s.raw_off,
            raw_size: s.raw_size,
            source,
            bytes_found,
            sha256_expected: s.sha256.clone(),
            sha256_actual: actual.clone(),
            match_ok: s.raw_size == 0 || actual == s.sha256,
        });
    }

    Ok((tail, placements))
}

/// Assemble the image and verify it against the recorded size and section
/// hashes.
pub fn rebuild_from_dump(dir: &Path, out: &Path, guess: HeaderGuess) -> Result<RebuildReport> {
    let full = load_dump(dir)?;
    let (tail, sections) = assemble_tail(dir, &full)?;
    let header = synthesize_header(&full, &guess)?;

    let mut img = Vec::with_capacity(header.len() + tail.len());
    img.extend_from_slice(&header);
    img.extend_from_slice(&tail);

    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(out, &img)?;

    let sha = crate::sha256_bytes(&img);
    let sections_ok = sections.iter().all(|s| s.match_ok);

    Ok(RebuildReport {
        schema_version: 1,
        dump_dir: dir.display().to_string(),
        out_path: out.display().to_string(),
        guess,
        size_expected: full.size,
        size_actual: img.len() as u64,
        size_ok: img.len() as u64 == full.size,
        sha256_expected: full.sha256.clone(),
        hash_ok: sha == full.sha256,
        sha256_actual: sha,
        sections,
        sections_ok,
        header_len: header.len() as u32,
        header_sha256: crate::sha256_bytes(&header),
        synthesised_fields: vec![
            format!("MajorLinkerVersion.MinorLinkerVersion = {}.{}", guess.linker_major, guess.linker_minor),
            format!("MajorOperatingSystemVersion = {}.{}", guess.os_major, guess.os_minor),
            format!("MajorImageVersion = {}.{}", guess.image_major, guess.image_minor),
            format!("MajorSubsystemVersion = {}.{}", guess.subsystem_major, guess.subsystem_minor),
            format!("SizeOfStackReserve = 0x{:x}", guess.stack_reserve),
            format!("SizeOfStackCommit = 0x{:x}", guess.stack_commit),
            format!("SizeOfHeapReserve = 0x{:x}", guess.heap_reserve),
            format!("SizeOfHeapCommit = 0x{:x}", guess.heap_commit),
            format!("COFF Characteristics = 0x{:04x}", guess.characteristics),
        ],
    })
}

/// How many axes a guess deviates from the linker defaults. Used to order the
/// sweep so the near-default combinations are tried first.
fn deviations(g: &HeaderGuess) -> u32 {
    let d = HeaderGuess::default();
    let mut n = 0;
    if (g.linker_major, g.linker_minor) != (d.linker_major, d.linker_minor) {
        n += 1;
    }
    if (g.os_major, g.os_minor) != (d.os_major, d.os_minor) {
        n += 1;
    }
    if (g.image_major, g.image_minor) != (d.image_major, d.image_minor) {
        n += 1;
    }
    if (g.subsystem_major, g.subsystem_minor) != (d.subsystem_major, d.subsystem_minor) {
        n += 1;
    }
    if (g.stack_reserve, g.stack_commit) != (d.stack_reserve, d.stack_commit) {
        n += 1;
    }
    if (g.heap_reserve, g.heap_commit) != (d.heap_reserve, d.heap_commit) {
        n += 1;
    }
    if g.characteristics != d.characteristics {
        n += 1;
    }
    n
}

/// The plausible values for each guessed field, most likely first.
///
/// The full product is ~280k combinations, which is far more than a stock
/// MSVC build needs. [`candidate_guesses`] sorts by [`deviations`], so the
/// default and every single-axis variant are tested in the first hundred
/// candidates and the exotic corners only get reached if nothing else hit.
fn candidate_guesses() -> Vec<HeaderGuess> {
    const LINKER: &[(u8, u8)] = &[
        (14, 29), (14, 28), (14, 30), (14, 31), (14, 32), (14, 33), (14, 34), (14, 35),
        (14, 36), (14, 37), (14, 38), (14, 39), (14, 40), (14, 41), (14, 42), (14, 43),
        (14, 44), (14, 0), (14, 1), (14, 10), (14, 11), (14, 16), (14, 20), (14, 21),
        (14, 22), (14, 23), (14, 24), (14, 25), (14, 26), (14, 27), (12, 0), (11, 0),
        (10, 0), (9, 0),
    ];
    const OSVER: &[(u16, u16)] = &[
        (6, 0), (6, 1), (6, 2), (6, 3), (10, 0), (5, 1), (5, 2), (4, 0),
    ];
    const IMGVER: &[(u16, u16)] = &[(0, 0), (1, 0), (0, 1)];
    const SUBVER: &[(u16, u16)] = &[
        (6, 0), (6, 1), (6, 2), (6, 3), (10, 0), (5, 1), (5, 2),
    ];
    const STACK: &[(u64, u64, u64, u64)] = &[
        (0x10_0000, 0x1000, 0x10_0000, 0x1000),
        (0x20_0000, 0x2000, 0x10_0000, 0x1000),
        (0x40_0000, 0x4000, 0x10_0000, 0x1000),
        (0x10_0000, 0x1000, 0x20_0000, 0x2000),
        (0x100_0000, 0x1000, 0x10_0000, 0x1000),
        (0x10_0000, 0x1000, 0x40_0000, 0x4000),
        (0x80_0000, 0x8000, 0x10_0000, 0x1000),
    ];
    const CHARS: &[u16] = &[0x22, 0x0022, 0x0002, 0x0023, 0x0102, 0x2022, 0x0000];

    let mut out = Vec::new();
    for &(lm, ln) in LINKER {
        for &(om, on) in OSVER {
            for &(im, inr) in IMGVER {
                for &(sm, sn) in SUBVER {
                    for &(sr, sc, hr, hc) in STACK {
                        for &ch in CHARS {
                            out.push(HeaderGuess {
                                linker_major: lm,
                                linker_minor: ln,
                                os_major: om,
                                os_minor: on,
                                image_major: im,
                                image_minor: inr,
                                subsystem_major: sm,
                                subsystem_minor: sn,
                                stack_reserve: sr,
                                stack_commit: sc,
                                heap_reserve: hr,
                                heap_commit: hc,
                                characteristics: ch,
                            });
                        }
                    }
                }
            }
        }
    }
    // Stable sort keeps the generation order inside each distance band, so the
    // sweep degrades gracefully: defaults, then one axis off, then two, and so on.
    out.sort_by_key(deviations);
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackReport {
    pub schema_version: u32,
    pub found: Option<HeaderGuess>,
    pub candidates: u64,
    pub tried: u64,
    pub threads: u32,
    pub elapsed_ms: u64,
    pub bytes_hashed: u64,
    pub note: String,
}

impl CrackReport {
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("# crack-header\n\n");
        s.push_str(&format!("- candidates: {}\n", self.candidates));
        s.push_str(&format!("- tried:      {}\n", self.tried));
        s.push_str(&format!(
            "- hashed:     {} bytes ({:.1} GB)\n",
            self.bytes_hashed,
            self.bytes_hashed as f64 / 1e9
        ));
        s.push_str(&format!(
            "- elapsed:    {} ms across {} threads\n",
            self.elapsed_ms, self.threads
        ));
        match &self.found {
            Some(g) => {
                s.push_str("\n**Recovered the exact header.**\n\n");
                s.push_str(&format!("- linker {}.{}\n", g.linker_major, g.linker_minor));
                s.push_str(&format!("- os {}.{}\n", g.os_major, g.os_minor));
                s.push_str(&format!("- image {}.{}\n", g.image_major, g.image_minor));
                s.push_str(&format!("- subsystem {}.{}\n", g.subsystem_major, g.subsystem_minor));
                s.push_str(&format!("- stack 0x{:x}/0x{:x}\n", g.stack_reserve, g.stack_commit));
                s.push_str(&format!("- heap 0x{:x}/0x{:x}\n", g.heap_reserve, g.heap_commit));
                s.push_str(&format!("- characteristics 0x{:04x}\n", g.characteristics));
            }
            None => {
                s.push_str("\nNo candidate reproduced the recorded hash.\n");
                s.push_str(&format!("{}\n", self.note));
            }
        }
        s
    }
}

/// Sweep the plausible linker defaults and return the first guess whose
/// reconstructed image hashes to the recorded value.
///
/// Each candidate costs one full pass over the image, so the work is split
/// across cores and the search stops on the first hit. `budget` caps how many
/// candidates are tried — `None` runs the whole space.
pub fn crack_header(dir: &Path, budget: Option<u64>) -> Result<CrackReport> {
    let full = load_dump(dir)?;
    let target = full.sha256.as_str();
    let (tail, _) = assemble_tail(dir, &full)?;
    let hdr_len = full.size_of_headers as usize;
    let opt_size: u16 = if full.is_64 { 240 } else { 224 };

    // Pre-build every header block once — 1 KB each, cheap next to the hashing.
    let mut cands = candidate_guesses();
    if let Some(b) = budget {
        cands.truncate(b as usize);
    }
    let headers: Vec<Vec<u8>> = cands
        .iter()
        .map(|g| synthesize_header(&full, g))
        .collect::<Result<_>>()?;

    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
        .min(32);
    let t0 = std::time::Instant::now();
    let tried = std::sync::atomic::AtomicU64::new(0);
    let hit = std::sync::Mutex::new(None::<usize>);

    let chunk = headers.len().div_ceil(threads as usize).max(1);

    std::thread::scope(|scope| {
        for (ci, chunk_headers) in headers.chunks(chunk).enumerate() {
            let tail = &tail;
            let tried = &tried;
            let hit = &hit;
            let base = ci * chunk;
            scope.spawn(move || {
                for (i, hdr) in chunk_headers.iter().enumerate() {
                    if hit.lock().map(|g| g.is_some()).unwrap_or(true) {
                        return;
                    }
                    let mut h = Sha256::new();
                    h.update(hdr);
                    h.update(tail);
                    let d = hex::encode(h.finalize());
                    tried.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if d == target {
                        if let Ok(mut g) = hit.lock() {
                            if g.is_none() {
                                *g = Some(base + i);
                            }
                        }
                        return;
                    }
                }
            });
        }
    });

    let idx = *hit.lock().unwrap();
    let elapsed = t0.elapsed();
    let n_tried = tried.load(std::sync::atomic::Ordering::Relaxed);
    let bytes = n_tried * (hdr_len as u64 + tail.len() as u64);

    Ok(CrackReport {
        schema_version: 1,
        found: idx.map(|i| cands[i]),
        candidates: headers.len() as u64,
        tried: n_tried,
        threads,
        elapsed_ms: elapsed.as_millis() as u64,
        bytes_hashed: bytes,
        note: format!(
            "The header block was never dumped, so it cannot be read back — only \
             reconstructed. This sweep covered {} combinations of the linker-default \
             fields (linker / OS / image / subsystem version, stack and heap sizes, COFF \
             characteristics).\n\
             \n\
             A miss does not mean the reconstruction is wrong. Two things sit outside the \
             search space entirely and would each be enough on their own:\n\
             \n\
             - the 64-byte DOS stub at 0x40, assumed to be the canonical MSVC one. \
               `e_lfanew` is 0x80, which leaves exactly 64 bytes for it, but a custom \
               `/STUB` would be a different 64 bytes and no field sweep can find it;\n\
             - the {pad} bytes of padding between the end of the section table (0x{sec_end:x}) \
               and `SizeOfHeaders` (0x{hdr:x}), assumed zero.\n\
             \n\
             Restoring the original from Defender's quarantine closes the gap exactly: diff \
             the restored header against the reconstructed one and every remaining byte \
             falls out. Until then the image written by `rebuild-pe` is runnable and every \
             section is byte-verified against the dump.",
            headers.len(),
            pad = (full.size_of_headers as usize).saturating_sub(off::OPT + opt_size as usize + off::SEC_ENTRY * full.sections.len()),
            sec_end = off::OPT + opt_size as usize + off::SEC_ENTRY * full.sections.len(),
            hdr = full.size_of_headers,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_full::SectionDump;

    fn fixture() -> PeFull {
        PeFull {
            schema_version: 1,
            path: "t.exe".into(),
            size: 0x400 + 0x200 + 0x400,
            sha256: "deadbeef".into(),
            e_lfanew: 0x80,
            machine: "0x8664".into(),
            is_64: true,
            image_base: 0x1_4000_0000,
            entry_rva: 0x1000,
            entry_va: 0x1_4000_1000,
            subsystem: 2,
            dll_characteristics: 0x8160,
            size_of_image: 0x3000,
            size_of_headers: 0x400,
            checksum: 0,
            timestamp: 0x6A_0000_00,
            sections: vec![
                SectionDump {
                    name: ".text".into(),
                    va: 0x1000,
                    vsize: 0x100,
                    raw_off: 0x400,
                    raw_size: 0x200,
                    chars: 0x6000_0020,
                    entropy: 0.0,
                    sha256: String::new(),
                    virtual_only: false,
                    executable: true,
                },
                SectionDump {
                    name: ".Ln,".into(),
                    va: 0x2000,
                    vsize: 0x100,
                    raw_off: 0,
                    raw_size: 0,
                    chars: 0x6000_0020,
                    entropy: 0.0,
                    sha256: crate::sha256_bytes(&[]),
                    virtual_only: true,
                    executable: true,
                },
            ],
            data_dirs: (0..16)
                .map(|i| crate::pe_full::DataDir {
                    index: i as u8,
                    name: "x".into(),
                    rva: 0,
                    size: 0,
                })
                .collect(),
            exports: vec![],
            debug: vec![],
            tls: None,
            resources: vec![],
            overlay_off: 0,
            overlay_size: 0,
            overlay_sha256: None,
            utf16_strings: vec![],
        }
    }

    #[test]
    fn header_is_the_recorded_length_and_carries_the_recorded_fields() {
        let f = fixture();
        let h = synthesize_header(&f, &HeaderGuess::default()).unwrap();
        assert_eq!(h.len(), 0x400);
        assert_eq!(&h[0..2], b"MZ");
        assert_eq!(&h[0x40..0x42], &DOS_STUB[0..2]);
        assert_eq!(&h[0x80..0x84], b"PE\0\0");
        assert_eq!(u32::from_le_bytes(h[0x3C..0x40].try_into().unwrap()), 0x80);
        // COFF
        assert_eq!(u16::from_le_bytes(h[0x84..0x86].try_into().unwrap()), 0x8664);
        assert_eq!(u16::from_le_bytes(h[0x86..0x88].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(h[0x94..0x96].try_into().unwrap()), 240);
        // Optional
        assert_eq!(u16::from_le_bytes(h[0x98..0x9A].try_into().unwrap()), 0x20B);
        assert_eq!(u32::from_le_bytes(h[0xA8..0xAC].try_into().unwrap()), 0x1000);
        assert_eq!(u64::from_le_bytes(h[0xB0..0xB8].try_into().unwrap()), 0x1_4000_0000);
        assert_eq!(u32::from_le_bytes(h[0xD0..0xD4].try_into().unwrap()), 0x3000);
        assert_eq!(u32::from_le_bytes(h[0xD4..0xD8].try_into().unwrap()), 0x400);
        assert_eq!(u16::from_le_bytes(h[0xDC..0xDE].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(h[0x104..0x108].try_into().unwrap()), 16);
        // Section table
        assert_eq!(&h[0x188..0x18E], b".text\0");
        assert_eq!(u32::from_le_bytes(h[0x188 + 8..0x188 + 12].try_into().unwrap()), 0x100);
        assert_eq!(u32::from_le_bytes(h[0x188 + 12..0x188 + 16].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(h[0x188 + 16..0x188 + 20].try_into().unwrap()), 0x200);
        assert_eq!(u32::from_le_bytes(h[0x188 + 20..0x188 + 24].try_into().unwrap()), 0x400);
        // Second section name with a comma survives the round trip
        assert_eq!(&h[0x188 + 40..0x188 + 44], b".Ln,");
    }

    #[test]
    fn derived_sizes_follow_the_section_characteristics() {
        let f = fixture();
        let h = synthesize_header(&f, &HeaderGuess::default()).unwrap();
        // .text is CNT_CODE, 0x200 raw bytes; .Ln, is CNT_CODE but disk-empty.
        assert_eq!(u32::from_le_bytes(h[0x9C..0xA0].try_into().unwrap()), 0x200);
        assert_eq!(u32::from_le_bytes(h[0xA0..0xA4].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(h[0xAC..0xB0].try_into().unwrap()), 0x1000);
    }

    #[test]
    fn alignment_is_recovered_from_the_section_table() {
        let f = fixture();
        // lowest non-zero va = 0x1000, lowest non-zero raw_off = 0x400
        assert_eq!(alignment(&f).unwrap(), (0x1000, 0x400));
    }

    #[test]
    fn a_header_that_cannot_hold_the_section_table_is_rejected() {
        let mut f = fixture();
        f.size_of_headers = 0x100;
        let e = synthesize_header(&f, &HeaderGuess::default()).unwrap_err();
        assert!(format!("{e}").contains("cannot hold"), "{e}");
    }

    #[test]
    fn a_non_canonical_entry_point_is_rejected() {
        let mut f = fixture();
        f.e_lfanew = 0x100;
        let e = synthesize_header(&f, &HeaderGuess::default()).unwrap_err();
        assert!(format!("{e}").contains("e_lfanew"), "{e}");
    }

    #[test]
    fn the_candidate_sweep_starts_at_the_defaults() {
        let c = candidate_guesses();
        assert_eq!(c[0], HeaderGuess::default());
        assert!(c.len() > 1000, "sweep should be broad, got {}", c.len());
    }
}
