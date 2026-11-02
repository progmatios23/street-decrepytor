# Street-decrepytor **v2**

Same tool as v1 (`D:\Street-decrepytor`) — **every v1 verb is forwarded** — plus live IDA-like views, better entropy, crypto-system reports, Unicorn.

Honesty contract is still parent [`../CRITICAL.md`](../CRITICAL.md). `decrypted=true` only on cipher transform or live `.text` grow.

## Install

```powershell
cd /d D:\Street-decrepytor\v2
pip install -e .
```

Parent v1 package is imported via `sys.path` (`compat.py` → `D:\Street-decrepytor`). No copy of v1 sources.

## Harvest + decrypt (v2.1)

`analyze` always dumps **everything** then tries real ciphers. Hits are written only when a header **beyond** the XOR key is valid (`PE\\0\\0`, ZIP method, PNG `IHDR`). Identity / header-forging XOR is rejected.

```
harvest/
  sections/  overlay.bin  resources/  carved_pe/  carved_magic/
  islands/   strings/     zlib/       pyinstaller/  HARVEST.json
decrypt/
  hits/*.exe|zip|png     DECRYPT.json    # kind=cipher only
```

```powershell
python -m street_v2 harvest TARGET.exe --out output\harvest
python -m street_v2 decrypt TARGET.exe
python -m street_v2 analyze TARGET.exe --out output\run
```

## What is better than v1

| Layer | v1 | v2 |
|-------|----|----|
| Pipeline | classify → static → protectors → deobf → crypto shapes | **same v1 stages**, then extra layers |
| Entropy | 64KB blocks, 32 stored | 4K sliding + χ² + **crypto islands** per section |
| Crypto | XOR/pxor/AES-NI *shapes* | **system detect → playbook** + `CRYPTO_SYSTEM_REPORT.md` |
| Disasm | Capstone listing | IDA-shaped **functions / xrefs / CFG** + HTTP |
| Emu | custom SIMD string emu | **Unicorn** xor/aes/call trace + optional v1 SIMD |
| Live | dump/Frida after spawn | **file watch + interval refresh** (IDA-like) |
| Report | `CRACK_REPORT.md` | **`ALL_ANALYSIS.md`** (v1 stages + v2 layers) |

## Commands

v2-native (upgraded):

```powershell
python -m street_v2 analyze TARGET.exe --out output\run --unpack
python -m street_v2 crack  TARGET.exe --unpack
python -m street_v2 live   TARGET.exe --interval 2
python -m street_v2 serve  --open TARGET.exe --port 39848
python -m street_v2 entropy TARGET.exe
python -m street_v2 crypto  TARGET.exe --out output\crypto
python -m street_v2 emu     TARGET.exe --simd
python -m street_v2 disasm  TARGET.exe --out output\disasm
```

v1 forwarded (identical jobs): `classify unpack dump pe-dump themida-unpack recover protectors junk strings deobf cfg memscan peb-patch frida-script frida-run recrack …`

```powershell
python -m street_v2 classify TARGET.exe
python -m street_v2 unpack TARGET.exe --live
python -m street_v2 dump --spawn TARGET.exe --wait 12 --vad --fix-pe --iat
```

## Analyze everything

`analyze` writes:

```
output/<stem>_v2/
  ALL_ANALYSIS.md              # operator report (read this)
  pipeline_result.json         # v1+v2 merged
  v1_pipeline_result.json      # raw v1
  CRYPTO_SYSTEM_REPORT.md|json
  entropy_map.json
  ida_view.json
  emu_trace.json
  v1_pipeline/<stem>_<sha12>/  # v1 stage JSON
```
