# UMI bin — Injection documentation (static, Street)

**Folder:** `C:\Users\LOZzzx\AppData\Roaming\umi\bin`  
**Tool:** `D:\Street-decrepytor-rs` (`street.exe`)  
**Date:** 2026-09-17  
**Honesty:** Nothing in this doc claims a live decrypt of the packed injector body. What is “already clear” is on disk without spawn.

## Files

| File | Size | SHA256 (prefix) | Disk state |
|------|------|-----------------|------------|
| `injector.exe` | 12 688 384 | `525c199da921…` | **PACKED** — `.text` raw=0, payload in `.iGL` (~12.1 MB, H≈7.82) |
| `module.dll` | 5 543 936 | `85e7fb81d176…` | **CLEAR** — no exports (manual-map style), ImGui/DX11 + Roblox HTTP |
| `support.exe` | 838 656 | `8589cf650f08…` | **CLEAR** — Luau compile/runtime helper |
| `luau-lsp.exe` | 17 116 672 | `0da4f09d474e…` | **CLEAR** — JohnnyMorganz `luau-lsp@1.69.0` + inject APIs present |

Outputs: `output/umi/{injector,module,support,luau-lsp}/`

---

## Architecture (injection chain)

```
                    ┌─────────────────────┐
                    │   injector.exe      │
                    │  PACKED host        │
                    │  empty .text on disk│
                    │  decrypts at runtime│
                    └─────────┬───────────┘
                              │ OpenProcess / map / inject
                              ▼
┌──────────────┐      ┌───────────────────┐      ┌────────────────┐
│ support.exe  │◄────►│   module.dll      │◄────►│ Roblox + APIs  │
│ Luau compile │      │  CLEAR payload    │      │ auth/economy/… │
└──────────────┘      │  ImGui DX11 overlay│      └────────────────┘
                      │  WinHTTP / mbedtls │
                      │  exports = 0       │
                      └───────────────────┘
                              ▲
                              │ often launched as IDE/LSP host
                      ┌───────┴───────────┐
                      │  luau-lsp.exe     │
                      │  real LSP + RPM/  │
                      │  VirtualAllocEx/  │
                      │  WriteProcessMemory│
                      └───────────────────┘
```

### Role of each binary

#### 1. `injector.exe` — packed injector host

- **Sections:** `.text/.rdata/.data/.pdata/.fptable` + custom `.:[f` all **virtual-only (raw 0)**.
- **Fat section:** `.iGL` @ file `0x600`, raw `0xc19000` — encrypted/runtime image.
- **Imports on disk:** stub-thin (`KERNEL32`/`USER32`/`ADVAPI32`/`bcrypt` — 1 name each). Real IAT appears after unpack.
- **Crypto ranking (Street):** `empty_text_runtime` + claimed `dw_stub` (density on whole file; densest window inside `.iGL` only ~8 ops → **stub auto-solve failed**, `decrypted=false`).
- **Conclusion:** Same class as Themida/custom section-decryptors. **Not decryptable offline with current Street auto-solver.** Needs live dump when `.text` fills, or a matched stub invert after reverse of the packer loop.

#### 2. `module.dll` — payload (already “decrypted” / clear)

- **No export directory** (`export RVA=0`) → intended for **manual map / reflective** load, not `LoadLibrary` by name.
- **Imports (clear):** `KERNEL32` (LoadLibrary/GetProcAddress/MapViewOfFile/CreateFileMapping), `WINHTTP` (full client), `bcrypt`, `CRYPT32`, `USER32`, `D3DCOMPILER_47`, CRT.
- **Strings (clear):**
  - Roblox hosts: `auth.roblox.com`, `economy.roblox.com`, `trades.roblox.com`, `billing.roblox.com`, `accountsettings.roblox.com`, `accountinformation.roblox.com`, `twostepverification.roblox.com`
  - Overlay: `imgui_impl_dx11`, `imgui_impl_win32`, `imgui.ini`
  - Internal: `umi.print('trust')`, `RenderJob`, Roblox XML serializer
  - TLS stack: mbedtls messages
- **Crypto shapes:** AES-NI (80), TEA delta, xor_imm — **no offline cipher hit** (`decrypted=false`). Crypto is for TLS/network, not a disk vault.
- **Street role:** `network_to_shared_memory` / overlay client.

#### 3. `support.exe` — Luau support process

- Almost only `KERNEL32` (+ LoadLibraryExW/GetProcAddress).
- Strings: full Luau FFlag / compile / bytecode surface (`LuauCompile*`, `LuauVirtualBcBuilder`, …).
- Helper for script compile/execute path used by the module, not the injector itself.

#### 4. `luau-lsp.exe` — LSP host with inject surface

- PDB: `D:\a\luau-lsp\luau-lsp\build\RelWithDebInfo\luau-lsp.pdb` → CI build of open-source luau-lsp.
- Branding: `luau-lsp@1.69.0`, `--platform roblox`, Sentry ingest URL.
- **Also imports:** `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`, `NtCreateThreadEx` (string), WinHTTP.
- Street role: `network_fetch_then_inject`.
- Interpretation: either a **patched/trojanized LSP** used as a living host, or bundled code that uses those APIs for tooling — treat as **injection-capable host** in this folder layout.

---

## Injection technique (from static evidence)

| Step | Who | Evidence |
|------|-----|----------|
| 1. Unpack | `injector.exe` | Virtual-only `.text`; fat `.iGL` |
| 2. Open target | injector / luau-lsp | `OpenProcess`, process APIs (after unpack / in LSP) |
| 3. Allocate + write | injector / luau-lsp | `VirtualAllocEx`, `WriteProcessMemory` |
| 4. Map payload | injector → `module.dll` | DLL has **zero exports**; `MapViewOfFile` / `CreateFileMapping` on module |
| 5. Thread | injector / luau-lsp | `CreateRemoteThread` / `NtCreateThreadEx` |
| 6. Overlay + net | `module.dll` | ImGui DX11 + WinHTTP to `*.roblox.com` |
| 7. Script | `support.exe` + module | Luau compile flags / `umi.print` |

This is **manual-map / remote-write injection** of a clear DLL, fronted by a **packed injector**.

---

## What Street did / did not decrypt

| Artifact | Offline decrypt? | Notes |
|----------|------------------|-------|
| `injector.exe` `.iGL` | **NO** | Packer; playbook = live dump / stub reverse |
| `module.dll` | N/A (already clear) | Full strings/imports/sections dumped |
| `support.exe` | N/A (clear) | Luau surface dumped |
| `luau-lsp.exe` | N/A (clear) | LSP + inject APIs dumped |

**“Tudo realmente já decryptado” is false for `injector.exe`.**  
It **is** true that the **payload DLL and helpers are already plaintext on disk** — Street extracted their full PE weight, imports, and strings without spawn.

---

## Street commands used

```bat
cd /d D:\Street-decrepytor-rs
set BIN=C:\Users\LOZzzx\AppData\Roaming\umi\bin

rem One shot — pe + extract + crypto + IDA strings + session (no stage skipped)
street complete %BIN% --out output\umi\complete
```

Verified `all_ok=true` for all 4 binaries (2026-09-17).

| Binary | IDA strings | with xrefs | notes |
|--------|-------------|------------|-------|
| injector | 2949 | 2 | packed — few code xrefs into clear strings |
| module | 8668 | 59 | ImGui/Roblox/mbedtls clear |
| support | 2212 | 457 | Luau FFlags heavily xref'd |
| luau-lsp | 18763 | 30 | real LSP surface |

Per-binary tree: `output\umi\complete\<name>\` → `pe\`, `crypto\`, `strings\STRINGS_IDA.txt`, `session\`, `COMPLETE.md`.

### IDA-style string format

```
.rdata:00000001804CBBB8  001Ch  C         XREF:3  "imgui_impl_dx11"
                 CODE XREF: sub_1803F2A10
```

Files: `STRINGS_IDA.txt`, `STRINGS_IDA.json`, `STRINGS_XREFS.txt`.

---

## Tool gaps exposed by this set (improve next)

1. **Packed injector:** prefer `empty_text_runtime` / live_dump over false `dw_stub` when fat-section dens is low.
2. **Role guess:** packed hosts must not report `native_tool` (fixed: `packed_injector_host` when virt≥3 + fat section).
3. **DLL with 0 exports:** flag explicitly as `manual_map_candidate`.
4. **Offline decrypt of `.iGL`:** still missing — needs stub geometry specific to this packer or runtime dump path.
