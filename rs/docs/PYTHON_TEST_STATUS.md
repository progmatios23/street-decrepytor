# Python tree test status (2026-09-16)

Workspace Python 3.12 without v1 extras.

## v1 `D:\Street-decrepytor\tests`

| Test | Result | Why |
|------|--------|-----|
| test_classify | pass | no extra deps |
| test_honesty | import error | `pefile` missing |
| test_stub_decrypt | import error | `capstone` missing |
| test_themida_oep | import error | `pefile` missing |
| test_potassium | import error | `pefile` missing |
| test_themida_unpacked.files_exist | pass | fixtures present |
| test_themida_unpacked.text_filled | pass | |
| test_themida_unpacked.stripped | OSError 22 | `injector_stripped.exe` unreadable |

## v2 `D:\Street-decrepytor\v2\tests`

| Test | Result | Why |
|------|--------|-----|
| entropy/shannon | pass | |
| decrypt xor/harvest | pass | |
| chacha/xor-add/opcode | pass | |
| cli_surface | import error | `click` missing |
| xor_flag_in_disasm | error | `capstone` missing |

Rust v2 tests replace the honesty/classify/stub/lift surface without those deps.
