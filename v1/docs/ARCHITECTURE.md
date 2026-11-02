# Street-decrepytor — Architecture

Contract for what actually runs (and what does **not** decrypt): [`../CRITICAL.md`](../CRITICAL.md).  
Module map: [`CODEMAP.md`](CODEMAP.md). CLI: [`CLI.md`](CLI.md). Rebuild order: [`REBUILD.md`](REBUILD.md).

## Goal

One CLI-first framework that classifies any build artifact, selects language-aware deobfuscation, recovers crypto *shapes* without hardcoded keys, detects commercial protectors behaviorally, and optionally attaches for live memory / API intercept — for AI agents and human reverse engineers.

## Design principles

1. **Re-derive, don't hardcode** — no eternal AOB/offset banks as sole authority. Patterns are *candidates*; confirmation is structural or dynamic.
2. **Language-agnostic shell, language-specific core** — `core/` never assumes C#. Routers dispatch to `deobf/*`.
3. **Stage isolation** — one stage failure never kills the pipeline.
4. **JSON-first I/O** — every command emits structured JSON for agent consumption.
5. **Evidence over folklore** — Potassium case study refuses inject claims without the child PE.

## Folder map

```
Street-decrepytor/
  street_decrepytor/
    core/           # classify, pipeline, engine
    static/         # PE/entropy/strings/junk
    dynamic/        # process scan, PEB patch, Frida plan
    deobf/
      csharp/       # ConfuserEx, SA, DNGuard, Agile, Obfuscar…
      java/         # JAR/class
      python_rt/    # pyc / PyInstaller / py2exe
      go_rt/        # pclntab path
      rust_rt/      # Tauri/Rust native (Potassium UI class)
      cpp_native/   # PE/ELF native
      mixed/        # C++/CLI
    protectors/     # Themida, VMProtect, generic packers
    crypto/         # XOR/SIMD/AES-NI shape recovery
    multibuild/     # embedded PE carve, containers
    potassium/      # official case study harness
    cli/            # click entrypoints
  docs/             # architecture, methodology, retrospectives, case studies
  tasks/            # task board + automation
  scripts/          # operator helpers
  tests/
  output/           # runtime reports (gitignored content ok)
```

## Pipeline

```
target path
   │
   ▼
classify_artifact ──► ArtifactProfile (family, arch, signals, protector candidates)
   │
   ▼
static.analyze ── entropy blocks, import scrape
static.strings ── interesting buckets
static.junk    ── Capstone density / opaque / timing
protectors.detect ── behavioral + weak named markers
multibuild.scan ── embedded PE carve
crypto.heuristics ── imm64 / pxor / rolling prefilter
deobf.route ── language engine + plan
dynamic.antidebug_plan
[optional] dynamic.process_scan  (STREET_ATTACH_PID)
   │
   ▼
output/<stem>_<sha12>/pipeline_result.json
```

## CLI surface

| Command | Purpose |
|---------|---------|
| `classify` | Family/arch only |
| `analyze` / `pipeline` | Full report |
| `protectors` | Packer/protector hits |
| `junk` | Junk/dead/vm-ish density |
| `strings` | Interesting strings |
| `deobf` | Language route |
| `frida-script` | API intercept JS |
| `memscan` | Live PID needle scan |
| `peb-patch` | BeingDebugged clear |
| `potassium` | Case study multi-root audit |

## Extension points

- Register a new deobf engine: implement `deobf_<lang>(profile, out_dir)` and branch in `deobf/router.py`.
- Register a pipeline stage: `StreetEngine.build_pipeline` → `pipe.add(name, fn, when=…)`.
- Protector playbooks: `protectors/<name>.py` returning step lists (per-build derivation notes mandatory).

## Non-goals (v0.1)

- Fully automatic commercial VM lifting (VMProtect/Themida) — playbooks + dump hooks only.
- Shipping stolen Hyperion internals as “Potassium inject”.
- Replacing IDA/Ghidra — integrates *with* them (idalib/MCP remain external).
