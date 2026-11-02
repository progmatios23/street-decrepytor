//! Static execution-profile facts that constrain what a live tool can do with a
//! binary.
//!
//! Two properties, both discovered the hard way while building the live tracer:
//!
//! 1. **Elevation.** A binary whose manifest requests `requireAdministrator`
//!    cannot be spawned — let alone debugged — from a non-elevated process.
//!    That is a static property of the file, but it was only being discovered at
//!    spawn time, as an opaque `ERROR_ELEVATION_REQUIRED`. Reporting it up front
//!    means the answer is known before anyone tries to run it.
//!
//! 2. **Direct syscalls.** A binary containing `syscall` (`0F 05`) instructions
//!    may bypass the DLL exports entirely. A breakpoint on an imported function
//!    never fires for those calls, so API-level tracing systematically
//!    under-reports such a binary. Counting the sites quantifies that blind spot
//!    *before* a trace is attempted, rather than leaving it as an unexplained
//!    absence of events.
//!
//!    The count has to be a count of *stubs*, not of byte pairs. Restricting a
//!    scan to executable sections assumes an executable section holds code —
//!    and a packed binary is exactly the case that violates it. `vector.exe`'s
//!    `.n00` is 45 MB of ciphertext marked executable, and `0F 05` occurs in it
//!    **704 times against 692.7 expected by chance**, sitting mid-family with
//!    `0F 01` (641), `0F 06` (471) and `0F 0B` (457). A byte-pair scan reports
//!    that as "704 direct syscall sites" and the number is pure noise. So each
//!    hit now has to look like the instruction sequence a syscall stub actually
//!    is — see [`direct_syscall_sites`].

use crate::pe::{parse_pe, section_bytes};
use serde::{Deserialize, Serialize};

/// `requestedExecutionLevel` values defined by the manifest schema.
pub const LEVEL_AS_INVOKER: &str = "asInvoker";
pub const LEVEL_HIGHEST_AVAILABLE: &str = "highestAvailable";
pub const LEVEL_REQUIRE_ADMIN: &str = "requireAdministrator";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProfile {
    /// `requestedExecutionLevel` from the embedded manifest, when present.
    pub requested_execution_level: Option<String>,
    /// The manifest demands elevation, so the process cannot be created from a
    /// non-elevated parent.
    pub requires_elevation: bool,
    /// Direct `syscall` stub sites inside executable sections — a `0F 05`
    /// preceded by a bounded `mov eax, <service number>`.
    pub direct_syscall_sites: usize,
    /// How many of [`Self::direct_syscall_sites`] also carry the
    /// `mov r10, rcx` that the x64 calling convention requires immediately
    /// before the service-number load. A site without it is still a syscall, but
    /// is not a stock stub, so it is worth seeing separately.
    pub direct_syscall_stub_shaped: usize,
    /// The first few of those addresses, for a human to inspect.
    pub direct_syscall_addrs: Vec<u64>,
}

impl ExecutionProfile {
    /// True when a live, non-elevated trace of this binary would be
    /// unrepresentative — either because it cannot start at all, or because it
    /// likely bypasses the API layer being instrumented.
    pub fn live_trace_is_unreliable(&self) -> bool {
        self.requires_elevation || self.direct_syscall_sites > 0
    }
}

/// Extract `requestedExecutionLevel` from the embedded manifest.
///
/// The manifest is stored as plain UTF-8 XML inside the resource directory, so a
/// byte scan for the element is simpler and more robust than walking the
/// resource tree — and it does not care which `RT_` type the resource was filed
/// under, which matters here because resource type naming in this codebase has
/// previously mislabelled a manifest.
pub fn requested_execution_level(data: &[u8]) -> Option<String> {
    let needle = b"requestedExecutionLevel";
    let mut from = 0usize;
    while let Some(rel) = find(&data[from..], needle) {
        let at = from + rel;
        // The `level` attribute sits inside the same element, close by.
        let end = (at + 200).min(data.len());
        if let Some(level) = extract_level(&data[at..end]) {
            return Some(level);
        }
        from = at + needle.len();
    }
    None
}

fn extract_level(window: &[u8]) -> Option<String> {
    let rel = find(window, b"level")?;
    let mut i = rel + b"level".len();
    // Skip whitespace and the `=` before the quoted value.
    while i < window.len() && (window[i] == b' ' || window[i] == b'=') {
        i += 1;
    }
    let quote = *window.get(i)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let start = i + 1;
    let mut j = start;
    while j < window.len() && window[j] != quote {
        j += 1;
    }
    if j <= start {
        return None;
    }
    let v = String::from_utf8_lossy(&window[start..j]).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Largest service number accepted in a `mov eax, <ssn>` when validating a
/// syscall stub. Windows has never had anywhere near this many services; the
/// bound exists to reject arbitrary 32-bit constants, and it is what turns the
/// check from "a byte pair" into "an instruction sequence".
const MAX_SSN: u32 = 0x400;

/// `mov r10, rcx` — the argument shuffle every x64 syscall stub performs, since
/// `syscall` takes its first argument in r10 rather than rcx.
const MOV_R10_RCX: [u8; 3] = [0x4C, 0x8B, 0xD1];

/// Validate the `0F 05` at `at`. Returns `(is_site, is_stub_shaped)`.
fn classify_syscall_site(bytes: &[u8], at: usize) -> (bool, bool) {
    if at < 5 || at + 1 >= bytes.len() {
        return (false, false);
    }
    if bytes[at] != 0x0F || bytes[at + 1] != 0x05 {
        return (false, false);
    }
    // `mov eax, imm32` is five bytes and sits immediately before the syscall in
    // every stub that has shipped.
    let m = at - 5;
    if bytes[m] != 0xB8 {
        return (false, false);
    }
    let ssn = u32::from_le_bytes(bytes[m + 1..m + 5].try_into().unwrap());
    if ssn == 0 || ssn > MAX_SSN {
        return (false, false);
    }
    let stub_shaped = m >= 3 && bytes[m - 3..m] == MOV_R10_RCX;
    (true, stub_shaped)
}

/// Count direct `syscall` stub sites inside executable sections.
///
/// A `0F 05` byte pair is not a syscall. In a packed binary the executable
/// section is ciphertext, and `0F 05` turns up there at exactly the rate chance
/// predicts — so a byte scan reports noise with the confidence of a finding.
/// This validates the surrounding instruction sequence instead:
///
/// ```text
/// 4C 8B D1        mov r10, rcx        (stub-shaped sites only)
/// B8 <ssn:u32>    mov eax, <service number>, bounded by MAX_SSN
/// 0F 05           syscall
/// ```
///
/// Requiring the bounded service number alone puts the false-positive rate at
/// roughly `1/256 * 1024/2^32 * 1/65536` per byte — about `6e-10` expected hits
/// across a 45 MB blob, i.e. none. The `mov r10, rcx` check is reported
/// separately rather than folded in, because a syscall reached through a
/// non-stock stub is still a syscall and should not be silently dropped.
///
/// Returns `(sites, stub_shaped, addrs)`.
pub fn direct_syscall_sites(data: &[u8]) -> (usize, usize, Vec<u64>) {
    let Ok(img) = parse_pe(data) else {
        return (0, 0, Vec::new());
    };
    let mut count = 0usize;
    let mut stub_shaped = 0usize;
    let mut addrs = Vec::new();
    for sec in img.sections.iter().filter(|s| s.executable()) {
        let bytes = section_bytes(data, sec);
        let base = img.va(sec.va);
        for i in 0..bytes.len().saturating_sub(1) {
            let (site, shaped) = classify_syscall_site(bytes, i);
            if !site {
                continue;
            }
            count += 1;
            if shaped {
                stub_shaped += 1;
            }
            if addrs.len() < 16 {
                addrs.push(base + i as u64);
            }
        }
    }
    (count, stub_shaped, addrs)
}

/// Build the profile for a raw artifact.
pub fn analyze(data: &[u8]) -> ExecutionProfile {
    let level = requested_execution_level(data);
    let (sites, stub_shaped, addrs) = direct_syscall_sites(data);
    ExecutionProfile {
        requires_elevation: level.as_deref() == Some(LEVEL_REQUIRE_ADMIN),
        requested_execution_level: level,
        direct_syscall_sites: sites,
        direct_syscall_stub_shaped: stub_shaped,
        direct_syscall_addrs: addrs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_xml(level: &str) -> Vec<u8> {
        format!(
            "<?xml version='1.0'?><assembly><trustInfo><security>\
             <requestedPrivileges><requestedExecutionLevel level='{level}' uiAccess='false' />\
             </requestedPrivileges></security></trustInfo></assembly>"
        )
        .into_bytes()
    }

    #[test]
    fn reads_require_administrator() {
        let d = manifest_xml("requireAdministrator");
        assert_eq!(
            requested_execution_level(&d).as_deref(),
            Some(LEVEL_REQUIRE_ADMIN)
        );
    }

    #[test]
    fn reads_as_invoker() {
        let d = manifest_xml("asInvoker");
        assert_eq!(requested_execution_level(&d).as_deref(), Some(LEVEL_AS_INVOKER));
    }

    #[test]
    fn reads_double_quoted_and_spaced_attributes() {
        let d = b"<requestedExecutionLevel  level = \"highestAvailable\" />".to_vec();
        assert_eq!(
            requested_execution_level(&d).as_deref(),
            Some(LEVEL_HIGHEST_AVAILABLE)
        );
    }

    #[test]
    fn a_manifest_without_the_element_yields_nothing() {
        assert_eq!(requested_execution_level(b"<assembly></assembly>"), None);
    }

    #[test]
    fn arbitrary_bytes_do_not_panic_or_match() {
        let noise: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert_eq!(requested_execution_level(&noise), None);
    }

    #[test]
    fn elevation_is_flagged_only_for_require_administrator() {
        let mut p = analyze(&manifest_xml("requireAdministrator"));
        assert!(p.requires_elevation);
        assert!(p.live_trace_is_unreliable());

        p = analyze(&manifest_xml("asInvoker"));
        assert!(!p.requires_elevation);
    }

    #[test]
    fn non_pe_input_has_no_syscall_sites() {
        let (n, shaped, a) = direct_syscall_sites(b"not a pe at all");
        assert_eq!(n, 0);
        assert_eq!(shaped, 0);
        assert!(a.is_empty());
    }

    // ── syscall-site validation ─────────────────────────────────────────────
    //
    // The regression these lock in: a byte-pair scan over ciphertext reports
    // ~700 "syscall sites" in vector.exe's `.n00`, which is exactly the number
    // chance predicts for a 2-byte pattern in 45 MB. That number was carried
    // into three reports as fact.

    /// A stock x64 syscall stub: `mov r10, rcx; mov eax, ssn; syscall`.
    fn stub(ssn: u32) -> Vec<u8> {
        let mut v = vec![0x4C, 0x8B, 0xD1, 0xB8];
        v.extend_from_slice(&ssn.to_le_bytes());
        v.push(0x0F);
        v.push(0x05);
        v
    }

    #[test]
    fn a_stock_syscall_stub_is_counted_and_marked_stub_shaped() {
        let s = stub(0x30); // NtTerminateProcess
        let (site, shaped) = classify_syscall_site(&s, 8);
        assert!(site);
        assert!(shaped, "the mov r10, rcx prefix should be recognised");
    }

    #[test]
    fn a_syscall_without_the_r10_shuffle_is_counted_but_not_stub_shaped() {
        // mov eax, 0x18 ; syscall — a syscall, but not a stock stub.
        let mut v = vec![0xB8];
        v.extend_from_slice(&0x18u32.to_le_bytes());
        v.push(0x0F);
        v.push(0x05);
        let (site, shaped) = classify_syscall_site(&v, 5);
        assert!(site);
        assert!(!shaped);
    }

    #[test]
    fn a_bare_syscall_opcode_is_not_a_site() {
        assert_eq!(classify_syscall_site(&[0x0F, 0x05], 0), (false, false));
        assert_eq!(classify_syscall_site(&[0x90, 0x90, 0x0F, 0x05], 2), (false, false));
    }

    #[test]
    fn an_out_of_range_service_number_is_rejected() {
        // 0xBA41C16F is the kind of 32-bit constant that appears in ciphertext
        // immediately before a coincidental 0F 05.
        assert_eq!(classify_syscall_site(&stub(0xBA41_C16F), 8), (false, false));
        assert_eq!(classify_syscall_site(&stub(0), 8), (false, false));
        assert_eq!(classify_syscall_site(&stub(MAX_SSN + 1), 8), (false, false));
        assert_eq!(classify_syscall_site(&stub(MAX_SSN), 8).0, true);
    }

    #[test]
    fn a_syscall_opcode_that_is_not_0f05_is_not_a_site() {
        let mut v = vec![0x4C, 0x8B, 0xD1, 0xB8];
        v.extend_from_slice(&0x10u32.to_le_bytes());
        v.push(0x0F);
        v.push(0x0B); // ud2, not syscall
        assert_eq!(classify_syscall_site(&v, 8), (false, false));
    }

    #[test]
    fn ciphertext_yields_no_syscall_sites() {
        // Deterministic xorshift, so the assertion is reproducible. 64 KiB of
        // noise would produce ~1 raw `0F 05` under the old scan; the validated
        // check should produce none at all.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut noise = Vec::with_capacity(1 << 16);
        for _ in 0..(1 << 16) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            noise.push((state & 0xFF) as u8);
        }
        let raw = noise
            .windows(2)
            .filter(|w| w[0] == 0x0F && w[1] == 0x05)
            .count();
        assert!(raw > 0, "the fixture should contain raw 0F 05 pairs");

        let sites = (0..noise.len().saturating_sub(1))
            .filter(|i| classify_syscall_site(&noise, *i).0)
            .count();
        assert_eq!(sites, 0, "validated check must reject all {raw} raw pairs");
    }

    #[test]
    fn a_profile_with_syscall_sites_is_flagged_unreliable() {
        let p = ExecutionProfile {
            direct_syscall_sites: 3,
            ..Default::default()
        };
        assert!(p.live_trace_is_unreliable());
    }

    #[test]
    fn a_plain_profile_is_not_flagged() {
        let p = analyze(&manifest_xml("asInvoker"));
        assert!(!p.live_trace_is_unreliable());
    }
}
