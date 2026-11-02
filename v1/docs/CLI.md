# CLI catalog — Street-decrepytor

Entry: `python -m street_decrepytor` · `sdc` · `dist\street-decrepytor.exe` · `street.bat`

Source of commands: `street_decrepytor/cli/main.py` only. If it is not a `@main.command` here, it is not shipped.

`--help` English still says “decrypt”. [`CRITICAL.md`](../CRITICAL.md) is the contract.

## Groups

| Group | Verbs | Scope |
|-------|-------|--------|
| **Universal static** | `classify` `analyze` `pipeline` `protectors` `junk` `strings` `deobf` `cfg` `disasm` | any PE/JAR/pyc-like |
| **Honest extract** | `unpack` | copy confirmed resources; ID packer; never cipher |
| **Report one-shot** | `crack` `batch` `agent` | JSON/MD reports; may call recrack/SIMD as extras |
| **Live dump** | `dump` `pe-dump` `memscan` | Windows RPM. Packer decrypts itself; Street copies RAM |
| **Live detect** | `validate` `observe-syscalls` `stub-db` `stub-integrity` `peb-probe` `themida-phylo` `peb-patch` | Phase R. `clean ≠ safe` |
| **Hooks** | `frida-script` `frida-run` `syscall-map` `scyllahide-export` | emit / run intercept |
| **Potassium only** | `cdn-pull` `potassium` `capture-child` `recrack` `gates-apply` `simd-emu` | product. Not a generic cracker |
| **UI** | `dbg-server` | StreetDbg backend |
| **.NET helper** | `dotnet-analyze` | dnfile bridge + cctor *recipe* |

---

## Command → function

| Command | Implementation | Mutates target image? |
|---------|----------------|------------------------|
| `classify TARGET` | `core.artifact.classify_artifact` | no |
| `analyze TARGET --out --dynamic` | `StreetEngine.analyze` | no (JSON) |
| `pipeline` | alias of `analyze` | no |
| `protectors TARGET` | `protectors.detect.detect_protectors` | no |
| `junk TARGET` | `static.junk.stage_junk_scan` | no |
| `strings TARGET` | `static.strings.stage_string_scan` | no |
| `deobf TARGET` | `deobf.router.stage_deobf_route` | no (plan JSON) |
| `cfg TARGET` | `deobf.cfg_obfuscation.analyze_cfg` | no |
| `unpack TARGET [--live]` | `unpack_engine` + optional `themida_unpack` | copies; `--live` may add `runtime_dump` |
| `themida-unpack TARGET` | `protectors.themida_unpack.unpack_themida_live` | dumped PE + OEP patch if `.text` grew |
| `recover --farm --umi` | `core.recover.recover_target` | Farm extract + UMI tauri + injector strip |
| `crack TARGET` | `core.crack.crack_target` (+ optional unpack) | report; recrack only if Potassium-shaped DLL |
| `batch DIR` | `crack_batch` (skips >80MB, SIMD off) | per-file as crack |
| `agent [TARGET] --cdn --batch-dir` | crack + optional CDN + batch | same |
| `dump --spawn/--name/--pid` | `dynamic.pe_dump` | writes dump files; `--kill` kills **spawned** process |
| `pe-dump PID` | `dump_process_module` / `dump_all_modules` | dump files |
| `memscan PID --needle` | `dynamic.memory.scan_process_memory` | no |
| `peb-patch PID` | `antidebug.patch_peb_being_debugged` | **yes** — one PEB byte in live process |
| `validate [TARGET] --spawn/--pid` | `runtime.composite.validate_target` | may spawn/kill like dump |
| `observe-syscalls --pid` | `runtime.syscall_observatory` | no |
| `stub-db` | `runtime.stub_integrity.build_stub_db` | writes `data/stub_db/` |
| `stub-integrity --pid` | `validate_stubs_live` | no |
| `peb-probe --pid` | `runtime.peb_deception.probe_peb` | no |
| `themida-phylo TARGET [--pid]` | `runtime.themida_phylo` | no |
| `frida-script --family` | `dynamic.api_intercept.intercept_plan` | writes JS if `-o` |
| `frida-run TARGET` | `dynamic.frida_run` | needs `frida` on PATH |
| `syscall-map` | `dynamic.syscall_trace.harvest_ntdll_syscalls` | JSON + JS |
| `scyllahide-export` | `dynamic.scyllahide_profile` | INI |
| `disasm TARGET` | `disasm.engine.disassemble_pe` | listing JSON |
| `dbg-server` | `disasm.server.main_blocking` | blocking socket |
| `simd-emu TARGET` | `crypto.simd_emu.run_simd_emu_on_pe` | string JSON, not a PE |
| `dotnet-analyze TARGET` | `deobf.csharp.dnfile_bridge` | no |
| `cdn-pull` | `potassium.cdn.pull_product_stack` | downloads CDN bytes |
| `potassium` | `potassium.case.run_potassium_case` | scorecard |
| `capture-child` | `potassium.capture_child.write_capture_status` | procedure MD |
| `recrack DLL` | `potassium.recrack.recrack_dll` | **yes** — patched DLL (gates) |
| `gates-apply DLL --out` | recrack or legacy `gates.apply_gate_table` | **yes** |

---

## Operator sequences (no decrypt fantasy)

Unknown PE:

```
classify → unpack → (if themida_class) dump --spawn --wait 12 --vad --fix-pe --iat
                 → diff section raw sizes
         → (if resources PE/XML) use copies, stop
         → validate --spawn   # scores, not unpack
```

Potassium.dll:

```
cdn-pull --download
recrack <dll>
simd-emu <dll>          # only if .text exists on disk
potassium               # scorecard; inject_complete stays false without child
```

UMI:

```
unpack %APPDATA%\umi\bin\injector.exe
dump --spawn injector.exe --wait 10 --vad --fix-pe --iat
themida-phylo %APPDATA%\umi\bin\module.dll
cfg module.dll
python tools\run_frida_inject_trace.py
```

Do not run `simd-emu` on the packed injector as if it were unpack.

---

## Click groups that should exist (not implemented)

Today every verb is flat on `main`. Rebuild (see `REBUILD.md`):

```
sdc static     classify|analyze|strings|junk|protectors|deobf|cfg|disasm
sdc extract    unpack
sdc live       dump|pe-dump|memscan|validate|observe-syscalls|…
sdc k          cdn-pull|recrack|potassium|capture-child|simd-emu
sdc report     crack|batch|agent     # keep name, JSON field decrypted=false
```
