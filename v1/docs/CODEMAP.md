# Code map — Street-decrepytor

Line counts are physical lines in `street_decrepytor/` as of 2026-08-30. Empty `__init__.py` omitted.

## Layout

```
Street-decrepytor/
  street_decrepytor/          # installable package (the product)
  cli/main.py                 # all click commands live in ONE file (662)
  tests/                      # classify smoke only
  tools/                      # UMI injector emu + Frida traces (not imported by package)
  scripts/                    # operator one-offs (UMI, FarmServices, run_tasks)
  ui/streetdbg/               # ImGui disasm frontend → dbg-server
  data/stub_db/               # ntdll 32-byte hashes, Windows-build keyed
  docs/                       # this tree
  tasks/                      # TASK_BOARD + Phase R spec
  output/                     # runtime residue (not source)
  dist/street-decrepytor.exe  # pyinstaller
```

## Call graph (happy path)

```
cli/main.py
  ├─ classify ────────────── core/artifact.classify_artifact
  ├─ analyze / pipeline ──── core/engine.StreetEngine.analyze
  │                            └─ core/pipeline.Pipeline.run
  │                                 stages registered in engine.build_pipeline
  ├─ crack / batch / agent ─ core/crack.crack_target
  │                            ├─ StreetEngine.analyze
  │                            ├─ crypto/simd_emu.run_simd_emu_on_pe   (optional)
  │                            └─ potassium/recrack.recrack_dll       (if looks_k)
  ├─ unpack ──────────────── protectors/unpack_engine.unpack_target
  │                            ├─ identify_themida_class
  │                            ├─ extract_resources          (copy)
  │                            ├─ deobf/cfg_obfuscation      (if not themida)
  │                            ├─ crack_target on embedded PE
  │                            └─ dump_kit scripts (no dump executed)
  ├─ dump / pe-dump ──────── dynamic/pe_dump.*
  ├─ validate ────────────── runtime/composite.validate_target
  ├─ recrack / gates-apply ─ potassium/recrack | potassium/gates
  ├─ cdn-pull / potassium ── potassium/cdn | potassium/case
  ├─ cfg ─────────────────── deobf/cfg_obfuscation.analyze_cfg
  ├─ disasm / dbg-server ─── disasm/engine | disasm/server
  └─ runtime verbs ───────── runtime/{syscall_observatory,stub_integrity,peb_deception,themida_phylo}
```

`deobf/rust_rt/tauri_extract.stage_tauri_extract` exists and is **not** in `build_pipeline` and **not** called from `deobf/rust_rt/engine.py`. Dead stage.

---

## Package by directory

### `core/` — orchestration

| File | Lines | Job | Honest output |
|------|------:|-----|----------------|
| `artifact.py` | 277 | Magic + family + protector *candidates* | `ArtifactProfile` JSON |
| `pipeline.py` | 91 | Named stages, skip on fail, write `pipeline_result.json` | JSON |
| `engine.py` | 68 | Registers stages (static, protectors, crypto, deobf, antidebug, optional process_scan) | JSON |
| `crack.py` | 199 | One-shot report + SIMD + recrack heuristic | MD + JSON; optional patched DLL |

### `static/`

| File | Lines | Job |
|------|------:|-----|
| `analyzer.py` | 104 | PE/ELF entropy, imports, sections |
| `strings.py` | 109 | Noise-filtered interesting strings |
| `junk.py` | 96 | Capstone density / opaque / timing smells |

### `protectors/`

| File | Lines | Job | Decrypts? |
|------|------:|-----|-----------|
| `detect.py` | 113 | Markers + section names + IAT shape | no |
| `unpack_engine.py` | 438 | ID + resource copy + playbook + nested crack | **no** (see CRITICAL) |
| `themida.py` | 28 | Dict playbook only | no |
| `vmprotect.py` | 17 | Dict playbook only | no |

### `crypto/`

| File | Lines | Job |
|------|------:|-----|
| `recover.py` | 92 | `pxor` / AES-NI prefix hits; rolling XOR prefilter on file tail |
| `simd_emu.py` | 758 | Toy XMM interpreter on **disk** `.text` (Potassium-class strings) |
| `simd_xor.py` | 47 | Lane XOR helpers |
| `_simd_decrypt_v2_src.py` | 633 | Vendored ANALISTAR source — do not call from new code |

### `deobf/` — routers and **plans**

| File | Lines | Executes | Missing |
|------|------:|----------|---------|
| `router.py` | 39 | Dispatches on `LangFamily` | — |
| `cfg_obfuscation.py` | 120 | `lea+jmp` trampoline inventory | not a VM lift |
| `csharp/engine.py` | 144 | Marker regex + CFF byte density + plan | no IL restore |
| `csharp/dnfile_bridge.py` | 135 | Optional `dnfile` typedef sample | `dnfile` not in `pyproject.toml` |
| `java/engine.py` | 44 | JAR class list | — |
| `java/string_emu.py` | 112 | Constant-pool harvest | `xor_bruteforce_utf8` **never called** |
| `python_rt/engine.py` | 34 | Magic/PK/MEI detect + plan | no PYZ extract |
| `go_rt/engine.py` | 22 | Build-ID regex + plan | no pclntab |
| `rust_rt/engine.py` | 37 | Panic paths / crates / URLs | does not call `tauri_extract` |
| `rust_rt/tauri_extract.py` | 88 | HTML/JS carve + IPC inventory | **unwired** |
| `cpp_native/engine.py` | 25 | Junk score at file `0x1000` | no CFG fold |
| `mixed/engine.py` | 17 | csharp + native | same limits |

### `dynamic/` — live Windows

| File | Lines | Job |
|------|------:|-----|
| `pe_dump.py` | 509 | RPM dump, PE fix, IAT rewrite, spawn+**sleep**, VAD, Frida VP script emitter |
| `memory.py` | 146 | Process list, memscan |
| `antidebug.py` | 112 | Plan + `peb-patch` BeingDebugged |
| `api_intercept.py` | 81 | Frida JS templates |
| `frida_run.py` | 86 | Write script + subprocess `frida` |
| `syscall_trace.py` | 115 | ntdll SSN harvest + hook JS |
| `scyllahide_profile.py` | 71 | INI export |

### `runtime/` — Phase R (detect, not decrypt)

| File | Lines | CLI |
|------|------:|-----|
| `composite.py` | 262 | `validate` |
| `syscall_observatory.py` | 155 | `observe-syscalls` |
| `stub_integrity.py` | 211 | `stub-db`, `stub-integrity` |
| `peb_deception.py` | 192 | `peb-probe` |
| `themida_phylo.py` | 237 | `themida-phylo` |
| `common.py` | 132 | RPM helpers, error-margin blocks |

### `potassium/` — product-specific (not universal)

| File | Lines | Job |
|------|------:|-----|
| `cdn.py` | 439 | DoH + SNI pull |
| `case.py` | 300 | Scorecard B1–B6 |
| `recrack.py` | 180 | 52-gate wildcard patch |
| `gates.py` | 69 | Legacy exact-offset apply |
| `capture_child.py` | 95 | Hunt official child PE / write procedure |

### `disasm/` + `multibuild/`

| File | Lines | Job |
|------|------:|-----|
| `disasm/engine.py` | 337 | Capstone recursive + xrefs |
| `disasm/server.py` | 135 | JSON API for StreetDbg (`dbg-server`) |
| `multibuild/scan.py` | 67 | Embedded MZ carve (offset list + dump first hits) |

### `cli/`

| File | Lines | Job |
|------|------:|-----|
| `cli/main.py` | 662 | **All** commands. Split candidate — see REBUILD. |

---

## Outside the package (still on the bench)

| Path | Wired into CLI? | Notes |
|------|-----------------|-------|
| `tools/emul_injector.py` | no | UMI unicorn-ish emu; R-EMU7 still short-circuits |
| `tools/frida_inject_trace.js` + `run_frida_inject_trace.py` | no | Real UMI inject evidence (secmap) |
| `tools/stealth_frida_run.py` / `msgbox_watch.py` | no | First-run / MessageBox |
| `scripts/analyze_umi.py` / `analyze_umi_bin.py` | no | UMI static pass |
| `scripts/farmservices_real_crack.py` | no | Resource inflate; folder name `decrypted/` is a lie if streams=0 |
| `scripts/run_tasks.py` | no | Phase runner |
| `ui/streetdbg/` | via `dbg-server` | C++ ImGui. Root `imgui*.obj` are leftover build objects — not the pipeline |

---

## Tests

`tests/test_classify.py` only: minimal PE64 stub + zip/jar hint. No unpack, dump, recrack, simd, or runtime tests.

---

## Version pins (do not mix)

| Source | Value |
|--------|--------|
| `street_decrepytor/__init__.py` | `0.5.0` — trust this |
| `pyproject.toml` | `0.3.1` — stale |
| `pyproject.toml` deps | pefile, capstone, click, rich, pyelftools. **Not** listed: frida, dnfile, unicorn |
| Python | `>=3.11` |
