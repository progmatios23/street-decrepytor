# Rebuild list — features to remake completely

Sourced from the actual functions, not from README. Pair with [`CRITICAL.md`](../CRITICAL.md) (what must never be claimed) and [`CODEMAP.md`](CODEMAP.md) (where the code sits).

**Rule for every rebuild:** output must say whether bytes were *copied*, *patched*, or *transformed*. Transform = decrypt. Copy and patch are not decrypt.

Priority: **P0** = lying or unwired today · **P1** = half-engine that should become real or be renamed · **P2** = organize / depth.

---

## P0 — stop the lie, wire what already exists

### R-P0.1 Version pin
| | |
|--|--|
| Now | `__init__.py` = `0.5.0`, `pyproject.toml` = `0.3.1` |
| Target | single source, `pyproject` reads package version |
| Files | `pyproject.toml`, `__init__.py` |

### R-P0.2 `crack` / `unpack` report contract
| | |
|--|--|
| Now | `verdict.ready_for_dynamic` = static stages did not throw. `layers_removed` includes copies and CFG inventory. CLI help says decrypt. |
| Target | every report has `image_transforms: []` with `{kind: copy\|patch\|cipher, layer, path}`. `decrypted: false` unless a cipher transform is listed. Drop or rename `ready_for_dynamic`. Split `layers_removed` → `copied` / `patched` / `inventoried`. |
| Files | `core/crack.py` `_render_md` + verdict; `protectors/unpack_engine.py` report builder; `cli/main.py` group docstring |

### R-P0.3 SIMD path hygiene
| | |
|--|--|
| Now | `crack.py` hardcodes `C:\Users\ggles\Downloads\ANALISTAR\server_files\funcs_list.txt`. Emu reads **disk** `.text`. Packed injector (raw=0) still enters the stage. |
| Target | no machine-local path. Skip SIMD if `.text` `SizeOfRawData < 0x1000`. Optional: run SIMD on **dump** PE, not disk packer. `funcs-list` only via CLI `--funcs-list`. |
| Files | `core/crack.py`, `crypto/simd_emu.py` `pe_text_map` / `run_simd_emu_on_pe` |

### R-P0.4 Wire `tauri_extract`
| | |
|--|--|
| Now | `deobf/rust_rt/tauri_extract.py` has `stage_tauri_extract`. Not in `engine.build_pipeline`. Rust engine does not call it. |
| Target | `deobf/rust` and pipeline stage `deobf.tauri` when signals include Tauri/WebView2. Assets land under run dir. |
| Files | `core/engine.py`, `deobf/rust_rt/engine.py`, `tauri_extract.py` |

### R-P0.5 Dead Java XOR
| | |
|--|--|
| Now | `xor_bruteforce_utf8` defined, never called. Command still named `string_emu`. |
| Target | either call it on high-entropy UTF8 blobs and report `kind: cipher` on hits, or delete the function and rename to `string_harvest`. |
| Files | `deobf/java/string_emu.py` |

### R-P0.6 UPX honesty
| | |
|--|--|
| Now | `static_unpack_possible = is_upx`. Playbook `"use upx -d"`. `upx` never executed. |
| Target | if `upx` on PATH: subprocess `upx -d -o out`. If not: `copied: false, note: upx_not_installed`. Never set unpack-possible without a file. |
| Files | `protectors/unpack_engine.py` |

### R-P0.7 Dump wait is a sleep
| | |
|--|--|
| Now | `spawn_wait_dump` = `CreateProcessW` + `time.sleep(wait_sec)` + RPM. Frida `dump_on_vp.js` is written by unpack kit, **not** used by the Python spawn path. |
| Target | wait on signal: RWX→RX via `VirtualProtect` hook (Frida subprocess) **or** poll `.text` entropy/size until delta, timeout = current `--wait`. Sleep-only remains as `--wait-mode sleep`. |
| Files | `dynamic/pe_dump.py` `spawn_wait_dump`, `cli/main.py` `dump` |

---

## P1 — remake the feature (half-engine → one real job)

Do not “add more plan JSON”. Either implement the transform or rename the verb.

### R-P1.1 Language deobf — pick one, finish it

All of `deobf/{csharp,java,python_rt,go_rt,rust_rt,cpp_native}` are plans (22–144 lines) except CFG inventory.

**Recommended first real engine: Python freezer extract** (bounded, no VM lift):

| | |
|--|--|
| Now | detect PK/MEI/PyInstaller, emit plan mentioning pyinstxtractor |
| Target | TOC walk, write `.pyc` to `out/pyz/`, JSON of names. Encrypted PYZ: re-derive key from bootstrap **or** `cipher: missing` — never fake plaintext. |
| Files | `deobf/python_rt/engine.py` (rewrite), tests on a tiny PyInstaller fixture |

**Second:** `.NET` optional subprocess `de4dot` when present; Street records tool version + hashes. Street does not become de4dot.

**Third:** Go `pclntab` parse enough to dump function names. Regex build-id is not that.

Leave VMProtect/Themida **out** of deobf engines. That path is dump.

### R-P1.2 `unpack` as extract-only module

Rewrite the report builder so the function name matches:

1. Identify (score + reasons) — keep
2. Extract resources — keep, label `copy`
3. Carve nested MZ — keep
4. CFG inventory — move to `cfg` only; do not list as layer removed
5. Packed section dump — label `copy_packed`, entropy attached
6. Never append “removed” for (4)

### R-P1.3 SIMD as Potassium-string tool, not crack extra

| | |
|--|--|
| Now | auto-runs inside `crack` for any native PE |
| Target | `simd-emu` stays. `crack` calls it only if `family in (native, rust)` **and** `.text` raw > 0 **and** pxor density. Document: output is `simd_strings.txt`, image unchanged. |

### R-P1.4 Recrack isolation

| | |
|--|--|
| Now | `crack` on any 8–15MB DLL containing `b"Potassium"` in first 1MB tries recrack |
| Target | recrack only from `recrack` / `gates-apply` / `cdn-pull --crack`. Universal `crack` must not patch a random DLL. |

### R-P1.5 Tests that pin honesty

| Fixture | Assert |
|---------|--------|
| minimal PE | classify format=pe |
| FarmServices-class (or a tiny PE+RCDATA MZ) | unpack `themida_class=false`, resource copy exists, `decrypted=false` |
| zero-raw `.text` fake | unpack `dynamic_required`, no cipher transform |
| Potassium-shaped bytes without gate table | recrack `ok=false`, no silent patch |
| SIMD on empty `.text` | skipped, not `unique_strings` theater |

Today: `tests/test_classify.py` only.

### R-P1.6 `tools/` → package or stay labeled lab

`emul_injector.py` + Frida traces are the UMI inject truth but live outside the package. Either:

- `street_decrepytor/lab/umi_emu.py` + CLI `lab umi-emu`, or
- `tools/README.md` stating **not shipped**, R-EMU7 OPEN

Do not let agents think `emul_injector` decrypts INJECT (it short-circuits).

---

## P2 — organize the tree

### R-P2.1 Split `cli/main.py` (662 lines)

Flat `@main.command` soup. Target click groups as in [`CLI.md`](CLI.md). Keep old names as hidden aliases so agents do not break.

Suggested files:

```
cli/main.py          group + version
cli/cmd_static.py
cli/cmd_extract.py
cli/cmd_live.py
cli/cmd_k.py
cli/cmd_report.py
```

### R-P2.2 pyproject extras

```
[project.optional-dependencies]
dotnet = ["dnfile"]
frida = ["frida", "frida-tools"]
emu = ["unicorn"]   # only if lab emu is packaged
```

CLI already imports these optionally; extras make the contract visible.

### R-P2.3 Stale spec vs TASK_BOARD

Rewrite `tasks/RUNTIME_BEHAVIORAL_LAYER.md` checkboxes to DONE where code exists. Leave R1.5 / R-EMU7 OPEN. Agents reading `[ ]` re-implement Phase R.

### R-P2.4 Repo hygiene

- Root `imgui*.obj` / `main.obj` — build leftovers; gitignore + delete
- `crypto/_simd_decrypt_v2_src.py` — archive under `third_party/` or drop; `simd_emu.py` is the live port
- `output/` already residue; keep gitignored

### R-P2.5 Dump IAT quality score

`rebuild_iat_from_dump` writes names when pointers resolve. Add `iat_resolved / iat_slots` on the dump JSON. A dump with 3 imports on a 20MB image is not “unpacked”.

### R-P2.6 `dbg-server` + StreetDbg

Works as a disasm UI, not an unpacker. Document in StreetDbg header. Do not add “decrypt” buttons.

---

## Explicit non-goals (do not rebuild into these)

| Temptation | Why not |
|------------|---------|
| Static Themida/VMP lifter | Out of scope v0.x. Dump only. |
| Street-as-de4dot | Shell out or plan. Do not reimplement ConfuserEx anti-tamper. |
| Universal “crack” that patches any binary | recrack is Potassium gates only. |
| Emu that “finishes inject” without Frida evidence | R-EMU7. Frida secmap is the truth (`STREET_UMI_TRUTH.md`). |
| Claiming Java/Python/Go deobf done because router wrote JSON | plan ≠ transform |

---

## Suggested implementation order

```
R-P0.1 version
R-P0.2 report contract (copied/patched/cipher)
R-P0.3 SIMD skip empty .text + kill hardcoded funcs_list
R-P0.4 wire tauri_extract
R-P0.5 java xor: call or delete
R-P0.6 UPX subprocess or honest miss
R-P0.7 dump wait on VP/entropy
R-P1.5 tests for the above
R-P1.4 recrack out of universal crack
R-P1.1 python PYZ extract (first real deobf)
R-P2.1 split CLI
R-P2.3 fix Phase R spec checkboxes
```

Each PR must leave `CRITICAL.md` true. If a PR makes `unpack` decrypt something, that something is a **named cipher** with input/output hashes — not a packer VM.

---

**Home:** `D:\Street-decrepytor` (moved 2026-09-02). Implementation of this list is in-tree; see snapshot below.

## Feature status snapshot (one screen)

| Feature | Status after 2026-09-02 cut |
|---------|----------------------------|
| classify | real |
| unpack report | `copied` / `inventoried` / `image_transforms` / `decrypted` |
| dump wait | `--wait-mode text` polls `.text` RPM; `sleep` still available |
| IAT quality | `iat_resolved` / `iat_slots` / `iat_sparse` on dump meta |
| recrack | isolated — `crack` default `apply_gates=False`; `--gates` opt-in |
| simd | skip if `.text` raw < 0x1000; no ANALISTAR hardcoded list |
| tauri | wired in rust deobf + pipeline `deobf.tauri` |
| UPX | `upx -d` if on PATH, else `upx_not_installed` |
| Java xor | `xor_bruteforce_utf8` called on low-printable CP strings |
| Python PYZ | CArchive extract + zlib inflate; encrypted PYZ not faked |
| tests | `test_classify` + `test_honesty` (8 tests) |
| CLI | `commands.py` + groups `static` `extract` `live` `k` `report` |
| pyproject | version `0.5.0` + extras dotnet/frida/emu |
| Themida static decrypt | **still does not exist** |
| R1.5 ScyllaHide fixtures | OPEN |
| R-EMU7 | OPEN |
