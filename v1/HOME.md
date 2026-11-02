# Street-decrepytor — this is the home tree

**Path:** `D:\Street-decrepytor`

Moved from `C:\claude\grok-persona\Street-decrepytor` on 2026-09-02.

```bat
cd /d D:\Street-decrepytor
set PYTHONPATH=%CD%
python -m street_decrepytor --help
python -m unittest tests.test_classify tests.test_honesty -v
```

**v2 (live IDA-like / entropy / crypto reports / Unicorn):** `D:\Street-decrepytor\v2` — see `v2\HOME.md`

```bat
cd /d D:\Street-decrepytor\v2
pip install -e .
python -m street_v2 analyze <pe> --out output\run
python -m street_v2 serve --port 39848
```

Contract: `CRITICAL.md`  
Map: `docs/INDEX.md`  
Rebuild (implemented): `docs/REBUILD.md`
