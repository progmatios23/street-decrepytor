# Street-decrepytor v2 — live tree

**Path:** `D:\Street-decrepytor\v2`

v2 = **v1 pipeline (all verbs)** + IDA-like live + entropy islands + crypto-system reports + Unicorn.

```bat
cd /d D:\Street-decrepytor\v2
pip install -e .
python -m street_v2 --help
python -m unittest tests.test_entropy_crypto tests.test_cli_surface -v
python -m street_v2 analyze TARGET.exe --out output\run --unpack
python -m street_v2 live TARGET.exe --interval 2
python -m street_v2 unpack TARGET.exe --live
python -m street_v2 dump --spawn TARGET.exe --wait 12 --vad --fix-pe --iat
```

Parent v1: `D:\Street-decrepytor` · contract: `..\CRITICAL.md`
