# CRITICAL — Street-decrepytor

**This file overrides `README.md`, CLI help, `DELIVERY.md`, and every `CRACK_REPORT.md`.**  
Marketing names (`crack`, `unpack`, `decrypt`, `deobf`) are verbs for *pipeline runs*. They are **not** proof that a byte was decrypted.

**Verified against source:** 2026-08-30  
**Code pin:** `street_decrepytor/__init__.py` → `0.5.0`  
**Ignore:** `pyproject.toml` still says `0.3.1`.  
**Siblings:** [`docs/INDEX.md`](docs/INDEX.md) · [`docs/CODEMAP.md`](docs/CODEMAP.md) · [`docs/CLI.md`](docs/CLI.md) · [`docs/REBUILD.md`](docs/REBUILD.md)

---

## 0. Stop. It does not decrypt.

Street-decrepytor **does not**:

- lift the Themida / WinLicense / Oreans **VM** (handlers stay virtualized)
- statically decrypt Themida from disk (empty `.text` has nothing to emu)

**What `themida-unpack` does:** spawn, PEB patch, wait until packer fills `.text` in RAM, copy that image, fix PE, hunt OEP. `decrypted=true` only if `.text` raw disk→dump grows. Command: `street-decrepytor themida-unpack TARGET --wait 12`.
- decrypt VMProtect
- run `upx -d` (UPX is detected; unpacker is **not** invoked)
- restore ConfuserEx / DNGuard / Agile / SmartAssembly method bodies
- decrypt PyInstaller PYZ / Nuitka
- lift a commercial VM to C
- rewrite a packed PE into a clear PE on disk from static analysis
- decrypt UMI injector `.text` (disk raw size 0 — there is nothing to emu)
- finish Potassium inject (`eb49692a` child body **BLOCKED**)

What the packer encrypts, **the packer decrypts in its own process**. Street at best **copies RAM after a sleep** (`dump --spawn` → `CreateProcessW` + `time.sleep(wait_sec)` + `ReadProcessMemory`). That is a memory copy, not a cipher implementation.

If a report says the tool “decrypted / unpacked / cracked” a protector **without** a dump size-delta (disk `.text` raw=0 → dump `.text` raw>0), the report is false. Delete it.

---

## 1. What each verb actually writes

Only three code paths **mutate or emit new binary bytes**. Everything else is JSON/Markdown/JS playbooks.

| CLI verb | Code | Bytes on disk | Crypto? |
|----------|------|----------------|---------|
| `classify` | `core/artifact.py` | none (stdout JSON) | no |
| `analyze` / `pipeline` | `core/engine.py` | `*.json` only | no |
| `crack` | `core/crack.py` | `CRACK_REPORT.md`, `crack_report.json`, optional `crack_simd.json`, optional `*_recracked.dll` | **no packer decrypt.** SIMD may list *strings*. recrack **patches jumps** (auth gates), does not decrypt. |
| `unpack` | `protectors/unpack_engine.py` | PE **resources copied as-is**; packed section **raw copied as-is**; `THEMIDA_CLASS_PLAN.json`; dump_kit scripts | **no.** `layers_removed` is a misnomer — see §3. |
| `dump` / `pe-dump` | `dynamic/pe_dump.py` | `*.rawmem` + optional PE-header fix + IAT rewrite from live pointers | **no cipher.** RPM snapshot of whatever the target already decrypted in RAM. Wait is a timer, not OEP detection. |
| `recrack` | `potassium/recrack.py` | `*_recracked.dll` | **no.** Wildcard match + patch `jz/jnz` (52 gates). Auth bypass on Potassium.dll only. |
| `simd-emu` / crack SIMD | `crypto/simd_emu.py` | `simd_emu.json`, `simd_strings.txt` | **string XOR emu** on **on-disk `.text`**. Empty `.text` (Themida-class) → nothing useful. Does not write a decrypted PE. |
| `deobf` | `deobf/*/engine.py` | `deobf_*.json` **plans** | **no.** Marker scan + “run de4dot later”. |
| `cfg` | `deobf/cfg_obfuscation.py` | trampoline inventory JSON | **no.** Recovers `lea` targets; does not undo VM. |
| `validate` / `observe-syscalls` / `stub-db` | `runtime/*` | scores + ntdll stub hashes | **no.** Detection, not decrypt. |
| `frida-script` / `frida-run` | `dynamic/*` | `.js` hooks | **no.** Intercept plan. |
| `cdn-pull` | `potassium/cdn.py` | CDN files as served | download, not decrypt. |
| `protectors` / `junk` / `strings` | static + detect | JSON | no |

**Byte-mutating operations (complete list):**

1. Resource extract — copy `RT_*` blobs (already plaintext or already PE).
2. Packed-section dump — copy still-packed raw.
3. `dump` — copy process memory; fix `PointerToRawData = VA`; optional IAT pointer rewrite.
4. `recrack` — patch Potassium gate bytes.

Nothing else rewrites the target image.

---

## 2. Name lies (do not parse English as capability)

| Name in the product | Literal reading | Code reality |
|---------------------|-----------------|--------------|
| package blurb “decrypt / deobf / unpack framework” | it decrypts | classify + report + dump playbook |
| command `crack` | cracker | pipeline + markdown. Verdict is family/arch/stage counts. |
| command `unpack` | unpacker | detect + extract resources + write “run dump later” |
| field `layers_removed` | crypto layer stripped | resource copy, section copy, or CFG *inventory* (inventory is not a removal) |
| field `ready_for_dynamic` | safe/ready to dump | `stages_fail == 0` on the **static** pipeline |
| `deobf_java` / `string_emu` | string decryptor ran | constant-pool **harvest**. `xor_bruteforce_utf8` is **defined and never called**. |
| `deobf_dotnet` | IL restored | `ConfusedByAttribute` etc. + a de4dot *recipe* |
| `crypto.heuristics` | keys recovered | `pxor` / AES-NI *prefix* hits + rolling XOR on last `0x8000` bytes as prefilter |
| `static_unpack_possible: true` (UPX) | Street unpacked UPX | playbook string `"use upx -d"` — **upx is never executed** |
| Themida `honest_verdict` “runtime decrypt” | Street decrypted | “go dump; the packer will decrypt itself” |
| SIMD `unique_strings` | binary decrypted | printable snapshots from a toy XMM interpreter, Potassium-shaped, disk `.text` only |

CLI help in `cli/main.py` still says *“universal multi-language decrypt”* and *“one-shot crack/unpack”*. That string is marketing. This file is the contract.

---

## 3. `unpack` — what “layers_removed” really is

From `unpack_engine.py` (verified):

```
layers_removed appends:
  embedded_pe_resource     → write resource bytes (no transform)
  plain_xml_resource       → write XML that was already plaintext
  packed_section_dump      → copy high-raw section (still packed)
  cfg_trampoline_inventory → count lea+jmp stubs (no bytes removed)
```

`identify_themida_class`: score from markers + zero-raw sections + weird names + starved IAT. Threshold `>= 0.45`. That is **identification**, not unpack.

`static_unpack_possible = is_upx` — and then **no UPX unpacker runs**.

If `themida_class` and no dump has been taken, the payload is still encrypted **in the file you started with**.

---

## 4. `dump` — copy, not cipher

`spawn_wait_dump` (`dynamic/pe_dump.py`):

1. `CreateProcessW`
2. `time.sleep(wait_sec)` default ~8–12s
3. `ReadProcessMemory` of the module
4. `fix_memory_pe` (section raw pointers → VA)
5. optional IAT rebuild from live module bases

Failure modes that still produce a file:

- packer has not finished (sleep too short) → dump still packed / empty `.text`
- anti-debug killed the process → incomplete
- you dump the disk image by mistake → zero-raw sections remain

**Proof of a useful dump:** section raw size on dump **>** disk raw size for the virtual sections (canonical: UMI injector `.text` 0 → ~311052). No delta → no “unpacked”.

---

## 5. `crack` — report generator

`crack_target` does **not** implement a crack. It:

1. `classify` + `StreetEngine.analyze` (JSON stages)
2. optional `run_simd_emu_on_pe` if family is native/rust/go/mixed
3. optional `recrack_dll` if the file *looks like* Potassium (`name` or size 8–15MB + `b"Potassium"` in first 1MB)
4. writes `CRACK_REPORT.md`

Hardcoded contamination:

```
C:\Users\ggles\Downloads\ANALISTAR\server_files\funcs_list.txt
```

If that file exists, **every** native `crack` feeds ANALISTAR function VAs into the SIMD emu. Absent → emu scans SIMD shapes itself. Either way: **no PE rewrite**.

`verdict.notes` saying “Commercial protector — use pe-dump” is the honest branch. Treat `stages_ok` as “JSON stages did not throw”, nothing more.

---

## 6. SIMD — strings only, disk `.text` only

`crypto/simd_emu.py` is a port of ANALISTAR `simd_decrypt_v2` for **Potassium.dll-class** SSE XOR string decoders.

It maps **file** `.text` (`pe_text_map`). Themida-class binaries with `.text` `SizeOfRawData=0` give the emu an empty or wrong slice. Running `crack` on UMI `injector.exe` and celebrating `unique_strings` is the wrong layer.

Even on a clear Potassium.dll: output is `simd_strings.txt` (ASCII snapshots), not a decrypted image. Auth gates are a **different** pass (`recrack`). UI JS Brotli is a **different** layer (`deobf/rust` only *mentions* it; does not extract/decode brotli).

`crypto/recover.py`: finds instruction *shapes*. `rolling_xor_bruteforce_ascii` tries 1–4 byte keys on a tail sample. It does not emit a decrypted file.

---

## 7. Language “deobf” — plans on disk

| Engine | What it executes | What it does not |
|--------|------------------|------------------|
| `deobf/csharp/engine.py` | marker regex, raw `0x45`/`0x2B` density, dnfile typedef sample, writes a de4dot-style **plan** | no anti-tamper restore, no constant decrypt, no CFF undo |
| `deobf/java/engine.py` + `string_emu.py` | zip list + constant-pool UTF8 harvest + name hints (`decrypt`, `allatori`, …) | `xor_bruteforce_utf8` **dead code** (never called). No JVM emu. |
| `deobf/python_rt/engine.py` | magic/PK/MEI detect + plan strings (`pyinstxtractor` later) | no PYZ key re-derive, no extract |
| `deobf/go_rt/engine.py` | `Go build ID` / vendor path regex | no pclntab parse |
| `deobf/rust_rt/engine.py` | panic `.rs` paths, crate names, URL scrape | no brotli asset extract |
| `deobf/cpp_native/engine.py` | capstone junk score on a 0x4000 window at file offset `0x1000` | no CFG fold, no VM lift |
| `deobf/mixed/engine.py` | calls csharp + native | same limits |
| `deobf/cfg_obfuscation.py` | `lea rcx,[rip+disp]; jmp` inventory | not Themida; module.dll-class only |

`deobf_route.json` `"routed_to": "dotnet"` means **which plan file was written**. It does not mean the assembly is clean.

---

## 8. Product-specific (not universal)

**Potassium only:** `cdn-pull`, `recrack`, `potassium` case, ANALISTAR `funcs_list`. Recrack 52/52 on a *matched* build is a **gate patch**, not string decrypt, not Hyperion, not inject.

**UMI only:** `%APPDATA%\umi\bin\injector.exe` Themida-class (EP in `.QR%`, `.text` 0 raw). `module.dll` CFG trampolines, `themida-phylo` 0.0. Inject body = `NtCreateSection` + `NtMapViewOfSection` + DllMain stub — **not APC**. Street does not decrypt the injector; `dump --spawn` copies post-runtime image.

**FarmServices.exe:** not Themida, not VMProtect, not bcrypt-decrypt. Plain XML + embedded PE in resources. `unpack` copies those resources. Relabeling it as a protector crack is a regression.

**DFIR (1).exe:** Themida-class *structure* (zero-raw, EP in `.mmA`). Score is ID. Payload stays packed until a dump delta exists.

---

## 9. Evidence required (or the claim is illegal)

| Forbidden sentence | Legal only if |
|--------------------|----------------|
| “Street decrypted this” | never, for packers. Say “packer decrypted in RAM; dump copied N bytes; `.text` raw 0→X” |
| “unpacked Themida/VMP” | dump file exists, section raw delta proven, IAT not empty |
| “cracked” | name the actual action: resource extracted / gates patched / strings listed / RAM copied |
| “deobfuscated .NET/Java/Python” | external tool log (de4dot, dnSpy dump, pyinstxtractor) attached — Street only wrote a plan |
| “UPX unpacked” | `upx -d` was run **by you**; Street did not |
| “inject complete” | official child hash on disk (`eb49692a…`) **and** live map evidence. Stub PE = false |
| “AES/Themida string vault cracked” | SIMD string list from a **clear** `.text`, labeled as strings, not auth |
| “ready for dynamic” | ignore the field; decide from protector class + whether a live PID exists |
| “layers removed” | list the files and whether they were **copies** or **transforms**. Copies are not removal |

---

## 10. Laws

| # | Law |
|---|-----|
| L1 | Re-derive per sample. Yesterday’s RVA is a candidate. |
| L2 | No decrypt claim without a transform (input bytes → different output bytes of the **same** layer). Copy and patch are not decrypt. |
| L3 | Stage failure must not kill the JSON run. |
| L4 | Agents parse JSON. Prose is residue. |
| L5 | `unpack` never invents a crypto step. Packed remains packed until dump delta. |
| L6 | No `inject_complete` without official child hash. |
| L7 | Do not mix layers: UI auth, SIMD strings, packer shell, inject body, ntdll hooks. |
| L8 | Commercial VM → dump path only. No static “NOP the VM”. |
| L9 | Do not trust CLI/README words `decrypt`, `crack`, `unpack`, `deobf` as capability. Trust this table. |

---

## 11. Load-bearing files vs noise

**Code that is the product:**  
`cli/main.py` · `core/artifact.py` · `core/engine.py` · `core/pipeline.py` · `core/crack.py` · `protectors/unpack_engine.py` · `dynamic/pe_dump.py` · `runtime/composite.py` · `deobf/router.py` · `potassium/recrack.py` · `potassium/cdn.py`

**Docs that stay true if you discount their titles:**  
`docs/OPERATOR_GUIDE.md` (FarmServices / DFIR facts) · `docs/retrospective/PRIOR_FAILURES.md` · `output/handoff_deobf/STREET_UMI_TRUTH.md` · `tasks/TASK_BOARD.md` (phase pin; not capability)

**Do not treat as capability:**  
`docs/DELIVERY.md` (“full architecture shipped”) · `docs/ARCHITECTURE.md` goal sentence · `tasks/RUNTIME_BEHAVIORAL_LAYER.md` (checkboxes stale vs code) · `pyproject.toml` version · old `output/**/*.md`

---

## 12. Open gaps (honest, still not decrypt)

- T3.1 Potassium official child body — **BLOCKED** (token)
- R-EMU7 emu INJECT short-circuit — OPEN
- R1.5 ScyllaHide/Themidie fixtures — OPEN
- `validate` wired into `unpack`/`agent` — partial
- Java XOR brute — dead function
- UPX — detect only
- SIMD funcs_list — machine-local ANALISTAR path

---

## 13. Five-minute operator path (no decrypt fantasy)

```bat
cd /d D:\Street-decrepytor
set PYTHONPATH=%CD%
python -m street_decrepytor classify TARGET
python -m street_decrepytor unpack   TARGET --out output\unpack\<stem>
```

Read `honest_verdict`, `themida_class`, **file list** under `resources/` (copies), `layers_not_present`.

- Themida-class → `dump --spawn TARGET --wait 12 --vad --fix-pe --iat` then **diff section raw sizes**. No delta = still packed.
- FarmServices-class → use the extracted resource PE/XML. Stop looking for a VM.
- Potassium.dll → `recrack` (gate patch). SIMD strings if `.text` is real on disk. Not inject.
- UMI injector → dump + Frida secmap. Do not write APC. Do not run SIMD as unpack.
- `module.dll` → `cfg`, not `themida-phylo`.

Then open the JSON. If the JSON has no output PE with a proven raw-size delta, **nothing was decrypted.**
