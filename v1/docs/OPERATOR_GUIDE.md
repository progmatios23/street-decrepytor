# Street-decrepytor — guia do operador / agent

## Binário

```
D:\Street-decrepytor\dist\street-decrepytor.exe
```

Rebuild: `powershell -File build_exe.ps1`  
Ou: `python -m street_decrepytor …` (dev).

## Comandos principais

```bat
REM wrappers (preferem dist\exe)
street.bat --help
agent.bat --cdn --out output\agent

street-decrepytor.exe --help
street-decrepytor.exe agent sample.exe
street-decrepytor.exe agent --cdn --out output\agent
street-decrepytor.exe agent --batch-dir C:\Users\ggles\Downloads\ANALISTAR
street-decrepytor.exe crack C:\path\sample.exe --out output\sample
street-decrepytor.exe batch C:\Users\ggles\Downloads\ANALISTAR --glob *.exe
street-decrepytor.exe cdn-pull --download --crack
street-decrepytor.exe cdn-pull --token SEU_JWT --download --crack
street-decrepytor.exe recrack Potassium.dll --out Potassium_recracked.dll
street-decrepytor.exe potassium
```

### Recrack (gates em build NOVA)

CDN live `1332B6DB…` não bate offset-a-offset com a tabela antiga (`91DCA151`).  
`recrack` re-deriva com wildcard de rel32 + contexto (full → trim → bare_near):

- **52/52 OK** na DLL baixada do CDN (2026-08)
- Escreve `*_recracked.dll` + `*.gates.json` re-derivado

## CDN Potassium (não é downloader genérico)

1. Resolve `files.potassium.pro` via **DNS-over-HTTPS** (ignora `hosts` → 127.0.0.1).  
2. SNI/Host do produto.  
3. Paths com trailing-slash como o cliente real.  
4. `resource.version` vira nome opaco dos binários (`UJHTs….dll/.exe`).  
5. `hashes.Potassium.exe = eb49692a…` = child oficial listado; body legado pode exigir `--token`.  
6. Após pull: `crack output\cdn\potassium\bin\Potassium.dll`.

## FarmServices.exe — veredicto REAL (sem fingir Themida)

```bat
street-decrepytor.exe unpack C:\Users\ggles\Downloads\ANALISTAR\FarmServices.exe
```

| Camada | Presente? | Ação real |
|--------|-----------|-----------|
| Themida / Oreans | **NÃO** | EP em `.text`, seções normais, zero markers |
| VMProtect | **NÃO** | — |
| bcrypt decrypt | **NÃO** | só hash APIs (SHA) |
| XML Sysmon schema | **SIM** plaintext | extraído `RT_RCDATA/101` |
| PE embutido ~8.4MB | **SIM** | extraído `RT_RCDATA/102` → nested crack |

Não há criptografia Themida para “remover”. O que a ferramenta faz: **extrair o que está confirmado** e marcar ausente o que não existe.

## DFIR (1).exe — Themida-class REAL (estrutura)

```bat
street-decrepytor.exe unpack "C:\Users\ggles\Downloads\ANALISTAR\DFIR (1).exe"
```

- 5 seções zero-raw (`.text` vazio no disco), EP em `.mmA`, nomes `.A!?` / `.V00`
- score Themida-class **0.65** → gera `THEMIDA_CLASS_PLAN.json` + ScyllaHide
- **Não** inventa decrypt estático do VM — playbook dinâmico honesto

## unpack (comando)

```bat
street-decrepytor.exe unpack sample.exe --out output\unpack\sample
street-decrepytor.exe crack sample.exe --unpack
```

## dump / pe-dump (Themida-class e qualquer processo)

```bat
REM spawn → espera unpack → dump main + VAD + fix PE + IAT
street-decrepytor.exe dump --spawn "C:\path\DFIR (1).exe" --wait 12 --vad --fix-pe --iat --out output\dumps\dfir

REM processo já rodando
street-decrepytor.exe dump --name "DFIR (1).exe" --vad --fix-pe --iat

REM só módulo principal (Scylla-style)
street-decrepytor.exe pe-dump 1234 --fix-pe --iat --out dumped.exe
street-decrepytor.exe pe-dump 1234 --all-modules --out output\dumps\mods

REM Frida: dump quando VirtualProtect vira RX/RWX
street-decrepytor.exe dump --spawn target.exe --frida-script --out output\dumps\frida
frida -f target.exe -l output\dumps\frida\dump_on_vp.js --no-pause
```

`unpack` em Themida-class gera `dump_kit\`:
- `dump_spawn.bat`
- `dump_on_vp.js`
- `RUN_DUMP.txt`

## Disassembler + StreetDbg (UI estilo x64dbg)

```bat
REM Capstone recursive disasm (CLI / agents)
street-decrepytor.exe disasm FarmServices.exe --out output\disasm\farm
street-decrepytor.exe disasm "DFIR (1).exe" --out output\disasm\dfir --max-insns 20000
street-decrepytor.exe disasm sample.exe --listing-only

REM JSON API for the UI
street-decrepytor.exe dbg-server --port 39847

REM ImGui + DX11 front-end (Functions | CPU | Dump | Log)
ui\streetdbg\build.bat
ui\streetdbg\StreetDbg.exe
```

StreetDbg: File → Open PE (sobe o dbg-server sozinho), painéis CPU/Dump/Functions, menu Debug → dump/unpack.

## Phase R — runtime validate (probabilistic)

```bat
REM build pristine Nt* stub DB for THIS Windows build
street-decrepytor stub-db

REM live pillars against a PID
street-decrepytor observe-syscalls --pid 1234
street-decrepytor stub-integrity --pid 1234 --shots 3
street-decrepytor peb-probe --pid 1234

REM Themida phylo (file)
street-decrepytor themida-phylo "%APPDATA%\umi\bin\injector.exe"

REM composite S0/S1/S2 — spawn, probe, dump, report
street-decrepytor validate "%APPDATA%\umi\bin\injector.exe" --spawn --wait 8 --out output\runtime\validate_injector
street-decrepytor validate "%APPDATA%\umi\bin\module.dll" --out output\runtime\validate_module
```

Always: `manual_cross_check_required=true`, error margins listed, clean PEB ≠ safe.

## Batch ANALISTAR (testado)

| Sample | Family | Nota |
|--------|--------|------|
| FarmServices.exe | native_pe | DFIR rules |
| DFIR (1).exe | native_pe | packer-ish sections |
| AnyDesk (2).exe | native_pe | remote tool |
| memory.exe | native_pe | clean-ish |
| ntdll_dump*.dll | native_pe | dumps |

Cada um: `output/batch/analistar/<name>/.../CRACK_REPORT.md`

## Exit codes

- `0` ok  
- `2` cdn-pull com erros de step (ainda grava o que conseguiu)
