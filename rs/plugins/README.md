# Street x64dbg plugin

Build `street-x64dbg` (cdylib). Copy:

```
target\release\street_x64dbg.dll  →  <x64dbg>\plugins\street.dp64
```

Menus: Plugins bar, CPU disasm, dump, graph, memmap, symbols.  
Commands: `street.decompile`, `street.card`, `street.packet`, `street.anal`, …  
Run `street x64dbg` for the full table.

Hotkeys: Ctrl+Shift+D decompile, Ctrl+Shift+C card, Ctrl+Shift+E evidence packet.
