# Street-decrepytor — final delivery

**Date:** 2026-08-13  
**Root:** `D:\Street-decrepytor` (moved 2026-09-02)  
**Status:** Full architecture shipped · only CDN child capture remains external  

## Delivered surface

| Layer | Module / CLI |
|-------|----------------|
| Classify + pipeline | `sdc classify` · `sdc analyze` |
| Static | entropy, strings, junk |
| Protectors | Themida/VMProtect/UPX/.NET markers |
| Crypto | heuristics + **simd_emu** (ANALISTAR port) |
| Deobf | C# / Java / Python / Go / Rust / native / mixed |
| .NET depth | dnfile bridge + cctor dump recipe |
| Java depth | class constant-pool string emu |
| Dynamic | memscan, PEB patch, **frida-run**, **pe-dump**, **syscall-map**, ScyllaHide export |
| Multibuild | embedded PE carve |
| Potassium | case harness, scorecard B1–B6, capture-child procedure |

## Run final verification

```powershell
cd /d D:\Street-decrepytor
pip install -r requirements.txt -e .
python -m unittest tests.test_classify -v
python scripts\run_tasks.py --phase all
```

Outputs:

- `output/FINAL_DELIVERY.json`
- `output/potassium/potassium_case_report.json`
- `output/potassium/SCORECARD.md`
- `output/potassium/child/CAPTURE_CHILD.md`
- `output/phase2/scyllahide/street_scyllahide.ini`
- `output/phase2/syscall_map.json`

## Blocked (honest)

Official inject PE is not on this machine. Framework:

- classifies stub vs candidate vs official  
- refuses `inject_complete=true` without official hash  
- documents capture steps for lab use  

Everything else that can run offline **is implemented and wired**.
