# Retrospective — why prior decrypt / deobf / crack attempts failed

**Sources audited (2026-08-13):**
- `C:\Users\ggles\AppData\Local\Temp\opencode` (hundreds of one-off scripts, emulators, IDA dumps, krypton_tool)
- `C:\claude\cracked` (pack docs, recrack, mock API, gate tables)
- `C:\Users\ggles\Downloads\ANALISTAR` + `server_files` (IDA analyses, simd_decrypt, patch tables)
- `C:\claude\grok-persona\Argumento` (debate/refutation on MCP claims)

---

## 1. Executive root causes (cross-language)

### R1 — Tool sprawl without a pipeline
opencode accumulated `emul_*.py`, `fn_*.py`, `diff_*.log`, `dec_*.py` as session-local spikes. Knowledge did not consolidate into a single adaptive engine. Next agent re-derived the same PE header walk fifty times.

### R2 — Hardcoded offsets / wrong VA width
Documented failure: `0x140155B0` vs real `0x1400155B0`. Scripts silently analyzed empty space. Street rule: resolve symbols by structure (exports, string xrefs, section walk), never paste yesterday’s RVA as truth.

### R3 — Signature-only packer identification
krypton_tool improved this with heuristics, but many scripts still branched on section names alone. Custom / renamed Themida builds and Potassium’s *unpacked* Rust UI were mislabeled.

### R4 — Crypto algorithm mis-identification
Single-byte XOR and 2-byte brute force were applied to **SIMD lane XOR** string decoders in `Potassium.dll`. Algorithm was never “unknown AES” — it was structured SSE XOR with per-slot keys. Failure was **model of the cipher**, not missing compute.

### R5 — Conflating layers
| Layer | Reality | Common wrong claim |
|-------|---------|-------------------|
| UI JS auth | Brotli asset patch + mock API | “native crypto cracked” |
| DLL string crypto | SIMD-XOR per function | “Themida string vault” |
| DLL auth gates | 52 conditional patches | “8/9 pontos” docs |
| String IMM table | ~4206 decrypt sites | treated as auth gates |
| Inject | child PE spawn | `LoadLibrary` remote inject |
| Child binary | 138752 NOOP stub in packs | “injector ready” |

### R6 — Dynamic without anti-anti-debug plan
x64dbg attaches without PEB/QIP/heap neutralization hit packer shells; analysts blamed “unknown VM” when checks simply exited early.

### R7 — Success theater
Docs claiming F9 / in-game run without `:8225` client, or “attach worked” meaning only `drop_attach` kill+relaunch. Street case harness encodes **honest DONE criteria**.

---

## 2. Per-ecosystem failure notes

### C# / .NET obfuscators
Prior attempts often ran one de4dot config against everything:
- **ConfuserEx anti-tamper** invalidates static method bodies until runtime restore.
- **DNGuard HVM** leaves IL as stubs — static deobf reports “empty” wrongly.
- **Agile.NET** decrypts on invoke — offline IL looks garbage.
- **SmartAssembly** string encoding needs decryptor emulation, not regex.
- **Obfuscar** rename-only samples were over-engineered with control-flow tools.

### Java
String decryptors not executed; renamed hierarchies treated as packers; no multi-release JAR / fat jar carve.

### Python
PyInstaller TOC partially extracted; encrypted PYZ keys not re-derived from bootstrap; Nuitka native mistaken for “C++ malware packer”.

### Go / Rust
Stripped binaries declared “no symbols” despite pclntab / panic metadata. Rust Tauri UIs analyzed only as PE sections — **frontend assets ignored**, missing the real auth surface (Potassium).

### C++ native + commercial protectors
Themida/VMProtect approached with static unpack recipes from old blog posts. OEP/IAT rebuild must be **dump-driven**. Magicmida/Themidie present in ANALISTAR were under-integrated into a single workflow.

### Multi-build / multi-arch
Embedded PE and dual UI copies (25MB vs 78MB Potassium) analyzed as one sample; hashes mixed across docs.

---

## 3. What was actually correct (preserve)

From `AUDIT_FULL_2026-08-12.md`, `DOCUMENTACAO_TECNICA.md`, `ATTACH_FLOW_REPORT.md`, `RELATORIO_FINAL_POTASSIUM.md`, `server_files/simd_decrypt_v2.py`:

- UI JS Ife/xfe/Efe auth bypass — **real**
- Mock API contract at `127.0.0.1:8080` — **real**
- Decompiler IPv6-only + IPv4 proxy — **real**
- 52-gate DLL gold `91DCA151` vs clean `106461DA` — **real**
- Attach spawns **child** `bin\Potassium.exe`, not CRT inject — **real**
- Official child CDN hash missing → inject incomplete — **real**
- SIMD string decrypt emulator direction — **correct approach** (needs pipeline home)

---

## 4. Misleading / inaccurate documentation flags

| Claim | Verdict |
|-------|---------|
| “8 pontos” DLL crack | **Obsolete** — 52 gates |
| LoadLibrary = Potassium method | **False** for product path |
| F9 works without 8225 | **False** |
| attach_last = full inject | **Overclaim** |
| patch_table 4206 = auth | **False** — string IMM sites |
| bootkit-v2-2 helps Hyperion | **Wrong domain** |
| hosts unpin alone = free update | **Incomplete** — login token second lock |

---

## 5. How Street-decrepytor is exponentially better

1. **One entrypoint** `sdc analyze` replaces ad-hoc script archaeology.
2. **Classification before deobf** stops Rust UI being shoved through .NET tools.
3. **Crypto shape recovery** + optional emulator hooks, not global XOR.
4. **Gate verification** maps RVA→file offline against `dll_gates_sigs.json`.
5. **Multibuild carve** separates embedded/paired artifacts.
6. **Dynamic plan + Frida generation** without pinning absolute addresses.
7. **Case study module** encodes Potassium truth tests so agents cannot “hallucinate cracked inject”.
8. **Retrospective docs** live in-repo — next session starts from failures already named.

---

## 6. What prior engineers should have done differently

1. Freeze a **hash inventory** before patching (now automated in `potassium.case`).
2. Separate **auth**, **string crypto**, **packing**, **inject** workstreams with DONE gates.
3. Promote `simd_decrypt_v2.py` into a library module (done: `crypto/simd_xor.py` + heuristics) instead of Temp copies.
4. Treat krypton_tool packer/junk/antidebug as stages, not a side CLI.
5. Never ship stub child as success.
6. Cross-link IDA MCP sessions to pipeline outputs (profile.json next to .i64 notes).
