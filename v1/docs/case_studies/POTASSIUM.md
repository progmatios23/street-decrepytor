# Case study — Potassium (first official benchmark)

## Why Potassium

Notoriously “cracked” on auth surfaces yet **incomplete** on inject. Multiple languages/build forms appear in one product:

| Artifact | Stack | Protection |
|----------|-------|------------|
| `Potassium.exe` (UI) | Rust + Tauri + WebView2 | Mostly unprotected native; secrets in JS assets |
| `Potassium_new.exe` | Packed / crypter lineage | High entropy / runtime decrypt |
| `Potassium.dll` | Native C++ MSVC | SIMD-XOR strings + auth gates |
| `Decompiler.exe` | Native PE64 | IPv6 HTTP service |
| child `bin\Potassium.exe` | Inject PE | **Missing/stub in crack packs** |

If Street-decrepytor can classify, separate layers, verify gates, and refuse false “100% cracked” claims, the framework works for multi-build products.

## Product architecture (evidence-based)

```
UI (Tauri) ──HTTP──► api/files.potassium.pro  OR  mock :8080
   │
   ├─ attach ──spawn──► child Potassium.exe <pid>
   │                         │
   │                         └── injects Potassium.dll ──WS──► UI :8225
   │
   └─ Decompiler.exe listens [::1]:56535  (proxy 127.0.0.1→IPv6)
```

## Layer cracks — status

| Layer | Status | Evidence |
|-------|--------|----------|
| UI login wall | Cracked (JS) | Ife/xfe/Efe Promise.resolve patches |
| Mock API | Working | DOCUMENTACAO_TECNICA runtime logs |
| DLL auth gates | Cracked (gold) | 52 entries `dll_gates_sigs.json` → `91DCA151` |
| DLL strings | Partially recovered | simd_decrypt / strings_map |
| Official child inject | **Not present** | stub `419148FF` size 138752 |
| In-game script | Blocked on child | no :8225 without real inject PE |

## Street harness

```bash
python -m street_decrepytor potassium --out output/potassium
```

Scans known roots (cracked, ANALISTAR, opencode), classifies each unique hash, verifies gate table when DLL+JSON found, emits `potassium_case_report.json`.

## Benchmark scorecard (use after each run)

| Check | Pass condition |
|-------|----------------|
| B1 | UI sample classified rust/native_pe + tauri signal |
| B2 | DLL classified native_pe; crypto stage sees pxor/imm shapes |
| B3 | Gate table verdict gold/clean/partial matches hash label |
| B4 | Child stub detected if size/hash matches |
| B5 | Report does **not** claim inject-complete without official child |
| B6 | Multibuild does not merge UI 25MB with packed 16–78MB as one SHA |

## Lessons folded into framework

- String IMM patch tables ≠ auth gates  
- Batch/xcopy relaunch stories vs child spawn — both instruments exist; inject primitive is child-internal  
- Hyperion research (beta18) is **reference only**, not Potassium product path  

## Scorecard automation

`python -m street_decrepytor potassium` writes `output/potassium/SCORECARD.md` with B1–B6.

## Remaining external (not framework)

1. Capture official child `eb49692a…` — see `sdc capture-child` / `CAPTURE_CHILD.md`  
2. Feed child through `analyze --dynamic` + `frida-run`  
3. Live :8225 + in-game print  

SIMD emulator is **in-tree**: `crypto/simd_emu.py` + `sdc simd-emu`.  
