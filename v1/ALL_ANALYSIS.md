# ALL_ANALYSIS — Street-decrepytor lab run

**Date:** 2026-09-02  
**Tree:** `D:\Street-decrepytor`  
**Output:** `D:\Street-decrepytor\output\all_analysis\`  
**Question:** does Themida unpack *really* work, and can it emit a modified EXE without packer VM code?

**Short answer:**  
- Static `unpack` works and does **not** pretend to decrypt.  
- Live `themida-unpack` on DFIR **failed** (`CreateProcess 740` = elevation required). Not a decrypt.  
- Offline `themida-rebuild` on a **previous** UMI injector dump **did** emit a smaller PE: **20.7 MB → 426 KB**, dropping Oreans sections `.'?r` / `.QR%` / `.;1/`, keeping filled `.text` (311 052 bytes of real code, EP `0x1000`). That is a modified EXE without the VM blob. It is **not** a static disk decrypt.

---

## 1. Unit tests

Command: `python -m unittest tests.test_classify tests.test_honesty tests.test_themida_oep -v`  
Log: `01_unit_tests.txt`

**Result: 13/13 OK** (rc=0, 0.66s).

---

## 2. Classify (live files)

| Sample | Size | themida_class | score | EP section | virtual-only |
|--------|-----:|:-------------:|------:|------------|--------------|
| `DFIR (1).exe` | 21 015 040 | **true** | 0.65 | `.mmA` | `.text` `.rdata` `.data` `.pdata` `.A!?` |
| `FarmServices.exe` | 9 880 576 | false | 0.00 | `.text` | none |
| `AnyDesk (2).exe` | 10 370 048 | false | 0.00 | `.text` | none |

JSON: `02_classify.json`

---

## 3. `unpack` (static)

### DFIR — Themida-class, **decrypted=false** (correct)

- Verdict: packed layout, EP in `.mmA`, 5 zero-raw sections. No cipher.  
- Copies: manifest XML + packed `.mmA` blob (20 301 824 B) + `.rsrc`.  
- Dump kit written (`dump_spawn.bat`, ScyllaHide INI).  
- **No unpacked payload PE.** Static unpack cannot fill `.text` raw=0.

### FarmServices — **not Themida**, real extract

- Embedded PE `RT_RCDATA/102` 8 480 560 B copied.  
- Sysmon-like XML `RT_RCDATA/101` copied.  
- `decrypted=false`. Nested crack ran on the embedded PE.

### AnyDesk (2) — **not Themida**

- Embedded PE `RT_RCDATA/102` 8 360 376 B copied.  
- Same class as FarmServices (resource payload), not Oreans.

---

## 4. Live `themida-unpack` on DFIR — **FAIL**

Command:

```
python -m street_decrepytor themida-unpack "C:\Users\ggles\Downloads\ANALISTAR\DFIR (1).exe" --wait 14 --out output\all_analysis\themida_dfir
```

| Field | Value |
|-------|--------|
| themida_class | true |
| ok | **false** |
| decrypted | **false** |
| error | `CreateProcess 740` (`ERROR_ELEVATION_REQUIRED`) |
| unpacked_pe | none |
| elapsed | 1.68s (never waited for .text) |

The binary’s manifest demands admin. Street’s `CreateProcessW` does not elevate. **Live decrypt capture did not run.**

---

## 5. Modified EXE without packer VM — **PASS (offline dump)**

Input: prior lab dump  
`output\dumps\umi_injector\spawn\injector_dumped.exe` (20 766 720 B)  
— this dump already had `.text` raw **311 052** (runtime decrypt had happened in an earlier session).

Command path: `themida-rebuild` / `strip_packer_sections`.

| | disk dump | stripped |
|--|----------:|---------:|
| size | 20 766 720 | **425 984** |
| kept | `.text` `.rdata` `.data` `.pdata` `.fptable` `.rsrc` `.reloc` | same |
| dropped | | `.'?r` (7.5 MB), `.;1/`, `.QR%` (12.8 MB) |
| EP | | `0x1000` (text_start, score 1.0) |
| `.text` head | | `40 55 53 57 48 8D AC 24 …` (real x64 prologue) |
| `.text` first 256 nonzero | | 220/256 |

**Written:** `output\all_analysis\injector_stripped.exe`  
PE signature valid (`MZ` / `PE\0\0`). pefile parses 7 sections.

This is “generate EXE without part of the code”: Oreans VM sections removed. IAT/relocs of the stripped image are **not** proven loadable in a process (new task).

---

## 6. Does it “really work”?

| Claim | Verdict |
|-------|---------|
| Identify Themida vs not | **yes** (DFIR vs FarmServices/AnyDesk) |
| Static decrypt Themida `.text` | **no** — copies packer blob only |
| Live spawn+dump decrypt | **not on DFIR this run** (elevation 740) |
| Emit modified EXE minus VM sections | **yes, if you already have a filled dump** |
| Lift Oreans VM / recover all original code | **no** |
| FarmServices “Themida crack” | **false** — resource extract only |

---

## 7. Artifacts

```
output/all_analysis/
  01_unit_tests.txt
  02_classify.json
  03_themida_dfir.txt
  04_injector_rebuild.json
  results.json
  injector_stripped.exe          ← modified PE, 426 KB
  unpack_dfir/
  unpack_farmservices/
  unpack_anydesk/
  themida_dfir/                  ← fail report only
  ALL_ANALYSIS.md
```

---

## 8. How to re-run

```bat
cd /d D:\Street-decrepytor
set PYTHONPATH=%CD%
python scripts\run_all_analysis.py
python -m street_decrepytor themida-rebuild output\dumps\umi_injector\spawn\injector_dumped.exe --out output\all_analysis\injector_stripped.exe
REM live (needs admin if target has requireAdministrator):
python -m street_decrepytor themida-unpack "C:\Users\ggles\Downloads\ANALISTAR\DFIR (1).exe" --wait 14
```
