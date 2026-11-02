# CRITICAL — Street-decrepytor-rs v2

Same honesty contract as `D:\Street-decrepytor\CRITICAL.md`.

- `decrypted=true` only for transform kinds `cipher` or `runtime_dump`.
- Copy, patch, inventory are not decrypt.
- Native lift emits **C-like pseudocode**. It is not Hex-Rays, not a Themida/VMP lifter.
- Ghidra/IDA/Binja backends consume **JSON exports**. Missing export = `EvidenceGap`, never empty C.
- MCP tools default small. Full listings are opt-in (`disasm count`, `decompile max_chars`).
- x64dbg plugin registers menus/commands. The motor is native lift on dumped bytes.

Commercial VM → dump path (not this crate).
