# Street-decrepytor

**Universal multi-language decryption, deobfuscation, and unpacking framework**  
CLI-first for AI agents and reverse engineers. No eternal signature DB as sole authority — classify, re-derive, dump, verify.

## Install / .exe

```powershell
cd D:\Street-decrepytor
pip install -r requirements.txt
pip install -e .

# agent binary (~12 MB onefile)
powershell -ExecutionPolicy Bypass -File build_exe.ps1
# → dist\street-decrepytor.exe
dist\street-decrepytor.exe --help
dist\street-decrepytor.exe crack --help
```

Guia operador: [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md)

## Quick use

```powershell
# ONE-SHOT crack (preferred for agents)
dist\street-decrepytor.exe crack C:\Users\ggles\Downloads\ANALISTAR\FarmServices.exe --out output\farm
dist\street-decrepytor.exe batch C:\Users\ggles\Downloads\ANALISTAR --glob *.exe

# Potassium product CDN (DoH bypasses hosts pin)
dist\street-decrepytor.exe cdn-pull --out output\cdn\potassium --download
dist\street-decrepytor.exe cdn-pull --token <jwt> --download

# classify any artifact
python -m street_decrepytor classify C:\path\to\sample.exe

# full pipeline (static)
python -m street_decrepytor analyze C:\path\to\sample.exe --out output

# language-routed deobf plan
python -m street_decrepytor deobf C:\path\to\sample.dll

# protector / junk / strings
python -m street_decrepytor protectors sample.exe
python -m street_decrepytor junk sample.exe
python -m street_decrepytor strings sample.exe

# live helpers / dumps (Windows) — Themida-class
python -m street_decrepytor recover --farm --umi --wait 5
python -m street_decrepytor dump --spawn target.exe --wait 12 --vad --fix-pe --iat
python -m street_decrepytor themida-unpack target.exe --wait 12
python -m street_decrepytor unpack target.exe --live
python -m street_decrepytor dump --name target.exe --vad
python -m street_decrepytor pe-dump <pid> --fix-pe --iat --out dumped.exe
python -m street_decrepytor unpack target.exe
python -m street_decrepytor memscan <pid> --needle MZ
python -m street_decrepytor peb-patch <pid>
python -m street_decrepytor frida-script --family dotnet -o hooks.js

# official case study + full phase run
python -m street_decrepytor potassium --out output/potassium
python -m street_decrepytor simd-emu C:\claude\cracked\bin\Potassium.dll
python -m street_decrepytor syscall-map
python -m street_decrepytor scyllahide-export
python -m street_decrepytor capture-child
python -m street_decrepytor pe-dump <pid> --module Potassium.dll
python -m street_decrepytor frida-run <pid_or_name> --family native_pe
python scripts\run_tasks.py --phase all
```

## What it covers

| Area | Capability |
|------|------------|
| Formats | PE, ELF, JAR/ZIP, pyc, PyInstaller, tar/OCI hints, multi-embedded PE |
| Languages | C#/.NET, Java, Python, Go, Rust, C++ native, C++/CLI mixed |
| .NET obfuscators | ConfuserEx, SmartAssembly, DNGuard, Agile.NET, Obfuscar (+ Reactor/Babel/Eaz) plans |
| Protectors | Themida, VMProtect, UPX-class, generic virtual-section shells |
| Crypto | imm64 / SIMD-XOR / AES-NI *shape* recovery; rolling XOR prefilter only |
| Dynamic | process list match, memscan, PEB patch, Frida hook generator |
| First benchmark | **Potassium** multi-artifact truth harness |

## Docs

**Start here:** [CRITICAL.md](CRITICAL.md) (what this tool does **not** decrypt) · [docs/INDEX.md](docs/INDEX.md)

- [Code map](docs/CODEMAP.md) — every module, line counts, call graph
- [CLI catalog](docs/CLI.md) — command → function
- [Rebuild list](docs/REBUILD.md) — features to remake (P0–P2)
- [Architecture](docs/ARCHITECTURE.md)
- [Operator guide](docs/OPERATOR_GUIDE.md)
- [Multi-lang methodology](docs/methodology/MULTI_LANG_METHOD.md)
- [Prior failure retrospective](docs/retrospective/PRIOR_FAILURES.md)
- [Tool audit](docs/retrospective/TOOL_AUDIT.md)
- [Potassium case study](docs/case_studies/POTASSIUM.md)
- [Task board](tasks/TASK_BOARD.md)

## Design law

1. Re-derive per sample — no frozen offsets as ground truth.  
2. Stage isolation — partial reports beat silent failure.  
3. JSON always — agents parse `pipeline_result.json`.  
4. Evidence over folklore — especially Potassium inject.

## License / use

For analysis of software you are authorized to reverse. Physical-safety only notes in dynamic attach (don’t freeze production systems you don’t own).
