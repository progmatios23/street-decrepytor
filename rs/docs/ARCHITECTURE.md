# Architecture — street-decrepytor-rs

```
CLI / MCP / x64dbg plugin
            │
            ▼
     street-decompile::Registry
        native │ ghidra-json │ ida-json │ binja-json │ x64dbg-live
            │
            ▼
     street-lift (C printer)  ←  street-disasm (iced-x86 / A64)
            │
            ▼
     street-core (classify, PE, transforms)
```

## Token reduction (MCP)

Host decides default evidence. Model requests deltas.

| Tool | Typical tokens |
|------|----------------|
| session.open | profile ~80 |
| funcs.list (40) | ~200 |
| func.card | ~80 |
| evidence.packet | ~400 |
| decompile max_chars=4000 | opt-in |
| compare.backends 1200/ea | opt-in |

`bounded_json` prunes depth/width, keeps valid JSON, sets `truncated`.

Capability flags (`backends`) before calls — never dump "tool not found" into a prompt.

## x64dbg

`pluginit` / `plugsetup` / `plugstop` / `CBMENUENTRY`.  
Host `_plugin_*` resolved from `x64dbg.dll` via `GetProcAddress`.  
Menus on all 7 slots. Command set `street.*` in the same dbg command table.

## Honesty

`street-core::transform` — copy/patch/inflate/cipher/inventoried/runtime_dump.  
`decrypted_flag` only cipher + runtime_dump.
