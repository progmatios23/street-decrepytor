# Street status — verified 2026-09-16

Target of live CLI smoke: `target-\AutoDumper.exe` (130048 B).  
Unit tests: `cargo test --workspace` → **24 passed, 0 failed**.

## CLI smoke (AutoDumper)

| Command | Exit | Real result |
|---------|------|-------------|
| classify | 0 | PE x64, sections correct after opt-header fix |
| extract | 0 | 14 DLLs, 11 interesting imports, URL+SHM, role guess OK |
| full | 0 | All sections dumped, dirs/TLS/debug/PDB/resources |
| crypto | 0 | Ranking OK; **decrypted=false** (honest for this sample) |
| strings | 0 | Plaintext OK; **deobfuscated still noisy** |
| links | 0 | URL `mdk.lol`, PDB path |
| funcs | 0 | **Only 2 functions** — too weak for 64KB `.text` |
| lift | 0 | Emits C; thin (few real control structures) |
| session | 0 | 15 modules (1+14 DLLs), 1 enc flow, emu 1 insn |
| backends / kernel / x64dbg | 0 | Caps / driver absent / menu table |

Cs2-External crypto: **os error 225** (Windows Defender blocks read) — not a Street bug.

## What actually works

1. **PE parse** — headers, sections, entropy, data dirs, TLS, debug RSDS, resource blob, overlay=0.
2. **Host inventory** — imports (fixed data-dir index), role `network_fetch_then_inject`, URL/SHM/PDB.
3. **Crypto ranking** — shapes + playbook; Cs2 dw_stub offline decrypt verified earlier (header 7 dwords).
4. **IDA-like session tree** — per-DLL folders + externs.c + ENCRYPTION_FLOWS.
5. **Honesty filters** — identity XOR / jpeg-forge / tab-pad largely killed on AutoDumper crypto path.
6. **Unit tests** — all green.

## Problems (ours)

| Severity | Problem | Effect |
|----------|---------|--------|
| **P0** | Function recovery finds ~2 funcs | Pseudocode/IR almost empty; not IDA-class |
| **P0** | Entry micro-emu stops after 1 insn (`returned_0`) | No real decrypt/API trace from EP |
| **P1** | String “deobf” XOR still emits hundreds of garbage | Noise drowning real clears |
| **P1** | Lift is linear-ish C, weak structuring | Readable listing, not Hex-Rays |
| **P2** | Resource type naming wrong (manifest labeled CURSOR) | Cosmetic / path names |
| **P2** | Kernel not loaded | RPM fallback only — expected without `.sys` |
| **P2** | Ghidra/IDA/Binja backends need export dirs | Caps off until set |
| **P2** | UTF-16 string dump empty on AutoDumper | Scanner miss / few UTF-16 runs |
| **Env** | Defender 225 on Cs2 sample | Lab must exclude path or use copy |

## AutoDumper truth (from working tools)

- Clear PE, **no packed child**, no overlay.
- Payload **not inside** — runtime fetch `https://mdk.lol/s/e/5` + inject APIs + `Local\VBoxMemShared`.
- TLS: 3 callbacks same VA — not analyzed by emu yet.
- `.text` H≈7.99 — dense code, but our CFG/func pass does not open it.

## UMI stock (2026-09-26)

`%AppData%\Roaming\umi\bin\injector.exe` SHA `173cd5c21d600f839085f0d648c6e6706cf93f13600b5d3ca3b02c0d3d24b3d1` is **Themida** (`.themida`, `.boot`), not the older empty-`.text` host. Crypto primary `tea_delta` is a false lead — named protector section must outrank TEA. `module.dll` SHA `c55ba06c…` is clear: AES-NI ×80, Luau http_get/post/request, manual-map candidate (export RVA 0). `decrypted=false` both. Full write-up: workspa-ce `docs/UMI-FULL.md` and `docs/STREET-UNIVERSAL.md`.

## Next cuts (priority)

1. `attach-dump`: RPM after no-debug spawn when `.text` entropy rises. `live-dump` DEBUG_PROCESS is the wrong first cut on Themida/packed hosts.
2. `pick_primary`: section name `.themida` / `.boot` beats `tea_delta`.
3. Recursive + exception-dir function discovery (use `.pdata`).
4. Emu: follow CRT to real `main` / don’t stop on early ret from thunk; map IAT stubs.
5. String deobf: only `lea_xor_loop` + stack + high-score; drop bulk section XOR.
6. Lift: feed recovered funcs from (3), not just EP window.
