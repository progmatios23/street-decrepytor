# Versions

Three trees. They are not the same product.

| Tree | Path here | Language | What it actually is |
|------|-----------|----------|---------------------|
| **v1** | `v1/` | Python | Classify / pipeline / JSON reports. `dump --spawn` copies RAM. Does **not** decrypt Themida/VMP. |
| **v2** | `v2/` | Python + tiny kernel stub | v1 verbs + entropy islands + XOR harvest + Unicorn hook + `serve`. Same honesty contract. |
| **rs** | `rs/` | Rust | Debugger host (`DEBUG_PROCESS`) + iced-x86 + optional `StreetKernel` RPM. Not a plugin. |

**Not imported (too big / bins / duplicates):**

- `v2/output/harvest_*` XOR carves (keep the *code* in `v2/street_v2/extract`)
- `target-v2/Cs2-External (1).exe` 27 MB — analysis is `v1/ANALYSIS.md`
- `Street-decrepytor-rs/rework` 367 MB, `main-nucleo` 79 MB
- `STREET-tool` 1.2 GB (SFsociety, blobs)

Read **`v1/CRITICAL.md` before the README.** Marketing names (`crack`, `unpack`) are pipeline verbs, not crypto.

## How they relate

```
v1  python-m street_decrepytor classify|analyze|dump|recrack
v2  python-m street_v2 analyze|live|unpack   (wraps v1 + harvest)
rs  cargo run -p street-cli -- debug notepad.exe
```

Potassium: `v1/street_decrepytor/potassium/recrack.py` patches 52 gates. Official inject child still missing.

CS2 loader: offline dword-loop decrypt documented in `v1/ANALYSIS.md` — that work is **analysis**, not a Street CLI feature.
