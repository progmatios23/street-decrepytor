# Docs index — Street-decrepytor

Read in this order. Older reports do not override newer contracts.

| Order | File | Role |
|------:|------|------|
| 0 | [`../CRITICAL.md`](../CRITICAL.md) | **Contract.** What the tool does *not* decrypt. Overrides README/CLI English. |
| 1 | [`CODEMAP.md`](CODEMAP.md) | Every package module, line count, who calls whom. |
| 2 | [`CLI.md`](CLI.md) | Every click command → function. Universal vs Potassium vs UMI. |
| 3 | [`REBUILD.md`](REBUILD.md) | Features to remake completely, ordered, with target behavior. |
| 4 | [`ARCHITECTURE.md`](ARCHITECTURE.md) | Original design (intent). Discount the “universal decrypt” sentence. |
| 5 | [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md) | How to run on this bench (FarmServices / DFIR / recrack). |
| 6 | [`methodology/MULTI_LANG_METHOD.md`](methodology/MULTI_LANG_METHOD.md) | How classification *should* route. Engines behind the route are still plans. |
| 7 | [`retrospective/PRIOR_FAILURES.md`](retrospective/PRIOR_FAILURES.md) | Why previous sessions died. Do not repeat. |
| 8 | [`retrospective/TOOL_AUDIT.md`](retrospective/TOOL_AUDIT.md) | Prior tools (opencode / ANALISTAR). Inventory, not Street status. |
| 9 | [`case_studies/POTASSIUM.md`](case_studies/POTASSIUM.md) | Product case. Inject stays blocked without child hash. |
| 10 | [`HANDOFF_UMI_EMU.md`](HANDOFF_UMI_EMU.md) | UMI emu session. Pair with `output/handoff_deobf/STREET_UMI_TRUTH.md`. |
| 11 | [`DELIVERY.md`](DELIVERY.md) | Surface list from 2026-08-13. Not depth. |
| 12 | [`../tasks/TASK_BOARD.md`](../tasks/TASK_BOARD.md) | Phase R + T-TM pin. |
| 12b | [`../tasks/THEMIDA_UNPACK.md`](../tasks/THEMIDA_UNPACK.md) | Themida live unpack: done vs OPEN. |
| 14 | [`../ALL_ANALYSIS.md`](../ALL_ANALYSIS.md) | Lab run 2026-09-02: what actually worked. |
| 13 | [`../tasks/RUNTIME_BEHAVIORAL_LAYER.md`](../tasks/RUNTIME_BEHAVIORAL_LAYER.md) | Spec for `runtime/`. Status = TASK_BOARD, not the `[ ]` boxes. |

## Root files that are part of the product

| File | Role |
|------|------|
| `../README.md` | Install + command samples. Marketing language — CRITICAL wins. |
| `../pyproject.toml` | Deps + version `0.5.0`. |
| `../street.bat` / `../agent.bat` | Wrappers around `dist\street-decrepytor.exe` or `python -m`. |
| `../build_exe.ps1` | PyInstaller onefile. |

## What is not documentation

`output/**` is run residue. Re-run the command. Do not treat a week-old `CRACK_REPORT.md` as current capability.
