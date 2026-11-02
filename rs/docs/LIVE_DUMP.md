# Live dump — capture what a process injects, maps or downloads

`street live-dump` runs a target under the debugger and captures the memory it
creates at runtime: injected shellcode, manually-mapped images, RWX regions, and
the kernel drivers the target causes to load.

```bat
street live-dump TARGET.exe --out output\livedump --seconds 30
```

## Why this exists

Static analysis cannot see a payload that is fetched or unpacked at runtime.
`injector.exe` in the UMI set is the canonical example: its `.text` is
virtual-only on disk (raw = 0) and the real image only exists in RAM after the
packer runs. `street crypto` correctly reports `decrypted=false` for it — the
honest answer for a static pass. This command is the other half: it observes the
process live and captures the bytes once they exist.

## Coverage boundary — what this does NOT capture

Read this before trusting an empty result.

The tool observes **memory state**, not **causes**. It has **no network and no
file-system instrumentation**. Specifically it does **not** capture:

| Not captured | Why |
|---|---|
| The HTTP/HTTPS body or any network traffic | no WinHTTP / WinINet / `ws2_32` / ETW instrumentation |
| Any file-system write or file drop | no minifilter, no `ReadDirectoryChangesW`, no `NtWriteFile` hook |
| Activity in child processes | the target is spawned `DEBUG_ONLY_THIS_PROCESS` |
| A payload written to disk then `LoadLibrary`'d | it becomes `MEM_IMAGE`, which is excluded by design |
| A region created, used and freed between two scans | detection is polling-based (default every 500 ms) |

What it *does* capture is the endpoint: memory that becomes **private +
executable**. So an HTTP download is visible only if its payload is executed
from a private buffer; if it is written to disk and loaded normally, it is
invisible.

**An empty artifact list therefore does not mean "nothing happened".** It means
no private executable region was observed in the window you asked for.

Every report now states this explicitly. `LIVEDUMP.md` and `LIVEDUMP.json` carry a
`coverage` block declaring, for each mechanism, whether it was instrumented and
what looking through it produced:

| Status | Meaning | Information value |
|---|---|---|
| `observed_none` | instrumented, sampled for the whole window, nothing matched | **positive evidence of absence** |
| `observed` | instrumented, captures made | findings |
| `not_observable` | no instrumentation exists for this mechanism | **zero information** |
| `delta_only` | instrumented as a before/after delta, no attribution | partial |

These states are never collapsed into one message: "we looked and found nothing"
and "we could not look" carry completely different weight, and conflating them
manufactures false confidence. The report also declares `scan_mode`,
`scan_interval_ms` and `missed_between_scans`, because polling cannot see a
region created, used and freed between two ticks.

The CLI refuses to emit a report that would read as clean without declaring its
blind spots (`live::check_honesty`).

### Partial captures

A region larger than `--max-region` (default 8 MiB) is captured as a **prefix**,
and the artifact is marked `partial: true` with both the full region size and the
captured size. The `sha256` covers the prefix only. A truncated dump that
reported itself as complete would be worse than no dump, so this is explicit in
both the table and the per-artifact detail.

### Attribution

A capture is reported as a **fact** — *"these bytes existed in private executable
memory at time T"* — not a conclusion. Private executable memory is also produced
by legitimate JITs, so the report does not call a capture "injected shellcode";
that attribution is the analyst's inference.

See `deliverables/engineering-assurance/test-plan-livedump-capture-2026-09-20.md`
for the validation that established this boundary.

## What it does

1. Spawns the target with `DEBUG_ONLY_THIS_PROCESS`.
2. Walks the target's virtual address space with `VirtualQueryEx` on a timer.
3. Classifies every committed region and flags **injection candidates**.
4. Dumps each newly-appearing candidate to disk with provenance.
5. Snapshots the loaded kernel drivers before and after, and reports the delta.
6. Records `LOAD_DLL`, `CREATE_THREAD`, and process events on a timeline.

## What counts as an injection candidate

| Region | Backing | Candidate? |
|--------|---------|-----------|
| `MEM_IMAGE` | PE on disk | no — it is a real module |
| `MEM_MAPPED` | file / section | no |
| `MEM_PRIVATE` + executable | none | **yes** |
| `MEM_PRIVATE` + RWX | none | **yes** |
| `MEM_PRIVATE` + RW | none | no |

The test is *private memory that is executable*. Private means no file backs it,
so the bytes were written at runtime by the target, a packer, or an injector.

## Output layout

```
output/livedump/<pid>/
  LIVEDUMP.md          human report: artifacts, drivers, modules, timeline
  LIVEDUMP.json        same, machine-readable
  REGIONS.json         full committed-region inventory
  regions/
    0000_<base>_rwx.bin    captured bytes
    0001_<base>_exec.bin
```

Each artifact records base, size, sha256, Shannon entropy, whether the bytes
parse as a PE, a disassembly head, and harvested strings.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--out` | `output/livedump` | Output root |
| `--seconds` | 20 | Observation window |
| `--interval` | 500 | Memory scan interval (ms) |
| `--min-region` | 64 | Ignore executable regions smaller than this |

A short `--interval` catches fast injections; a long `--seconds` catches late
ones. Both cost CPU, so tune per target.

## Kernel drivers

`EnumDeviceDrivers` enumerates loaded kernel drivers. The tool snapshots the list
before the target starts and after it ends; the difference is what the target
caused to load.

This is a **delta, not attribution**: a driver appearing during the window is
consistent with the target loading it, but a concurrent unrelated load would also
show up. For attribution, correlate against `NtLoadDriver` / service-creation
events.

The driver list is independent of `\\.\StreetKernel`. Without the driver loaded,
memory reads use `ReadProcessMemory`, which cannot read memory that is paged out
or protected from the debugger — the kernel client's CR3 walk can.

## Honesty

Dumped bytes are raw captures from a live process.

- `pe=true` means the bytes parse as a PE image. That is a **`runtime_dump`**, and
  `CRITICAL.md` counts it as a decrypt — but it is not a cipher break.
- `pe=false` means the bytes did not parse; they are still captured and hashed.
- An empty artifact list means no private executable region appeared **in the
  window you asked for**. It does not prove the target injects nothing. Widen
  `--seconds`, shorten `--interval`, or let the target reach its payload stage.

## Verification

The detector is exercised by a benign self-allocating target
(`output/livetest/rwx_target.rs`), which calls `VirtualAlloc` with
`PAGE_EXECUTE_READWRITE` and writes a known marker. The dump reproduces the bytes
exactly (`48 31 c0 c3` + marker), confirming the capture path.

`crates/street-debug/src/live.rs` carries 9 unit tests over region
classification, the driver delta, string harvesting, and UTF-16 decoding.
