# Street v2.1 — one process

Debugger + disasm + C-pseudocode + auto-links + kernel RPM in **one** `street.exe`.  
Not an x64dbg plugin. The host *is* the debugger (Windows `DEBUG_PROCESS`), shaped after x64dbg's CPU/regs/dump/log — own engine, own IR, own project file.

Guide: `guia_ida_pro_diferencas_recriar_melhorar.md` (clean-room: problems, not a clone).

```
target.exe
    │
    ▼
[street.exe] ─────────────────────────────────────────────┐
  loader PE/ELF │ iced-x86 │ IR │ C lift │ auto-links     │
  debug loop    │ PAGE_GUARD OEP │ BP / step / run        │
  kernel RPM    │ \\.\StreetKernel  (optional fallback)   │
  MCP stdio     │ project JSON (Git-diffable)             │
└─────────────────────────────────────────────────────────┘
```

## Build

```bat
cd /d D:\Street-decrepytor-rs
cargo test --workspace
cargo build --release
```

## Run a binary like a debugger

```bat
target\release\street.exe debug C:\Windows\System32\notepad.exe
```

Keys: `F7` step · `F8`/`F9` run · `F2` BP at RIP · `Tab` CPU/dump · `q` quit  
Commands: `g` `t` `bp 0x140001000`

## Live dump — capture injected / downloaded memory

```bat
street live-dump TARGET.exe --out output\livedump --seconds 30
```

Spawns the target under the debugger and captures what only exists at runtime:
injected shellcode, manually-mapped images, RWX regions, and the kernel drivers
the target loads. Walks the address space with `VirtualQueryEx`, flags **private
+ executable** regions (no file backing ⇒ written at runtime), dumps each new one
with sha256 + entropy + PE check + disassembly head, and reports the
kernel-driver delta across the run.

```
output/livedump/<pid>/LIVEDUMP.md   artifacts · drivers · modules · timeline
                      REGIONS.json  full committed-region inventory
                      regions/*.bin captured bytes
```

The interactive `debug` host runs the same scan on OEP/guard, DLL load, and
thread creation, logging `DUMP 0x…` lines as it captures.

**Coverage boundary:** this observes *memory*, not *causes*. There is no network
and no file-system instrumentation, so HTTP downloads and file drops are **not**
captured as such — only the private executable memory a payload may end up in.
An empty result does not mean nothing happened. Read `docs/LIVE_DUMP.md` before
trusting a negative.

Details and the honesty caveats: `docs/LIVE_DUMP.md`.

## Live trace — what the target calls, in order

```bat
street trace TARGET.exe --out output\trace --seconds 30
```

Runs the target under the debugger and records the **API calls** it makes, with
timestamps, arguments and caller attribution, from initial load through shellcode
execution. Resolves the target's Import Address Table at runtime and breakpoints
the resolved function addresses; on each hit it reads the argument registers and
the return address.

Because the caller's return address is on the stack at entry, a call originating
outside every mapped module is identifiable as **shellcode**:

```
seq 15  VirtualAlloc  args=[0x0, 0x1000, 0x3000, 0x40]  caller=image:target.exe+0x183e
seq 16  VirtualAlloc  args=[0x0, 0x1000, 0x3000, 0x40]  caller=private_exec   ← shellcode
seq 17  exec_in_private_memory
```

```
output/trace/<pid>/EVENTS.jsonl   one JSON object per line, ordered by seq
                   TRACE.json     summary + coverage block
                   TRACE.md       categories, modules, coverage, notes
```

Filter with `--categories memory,process,network,file`; cap cost with
`--max-armed` and `--max-events`. Exits non-zero if the trace is incomplete.

**Scope boundary:** from user mode only the **API call** is observable. Syscalls
are not directly visible, **direct-syscall stubs bypass the DLLs entirely and are
invisible**, child processes are not debugged, and payload bytes are not
captured — only the call. See `deliverables/engineering-assurance/live-trace-2026-09-20.md`.

## Static crypto (primary — no spawn)

```bat
street crypto TARGET.exe --out output\crypto\run
street crack  TARGET.exe --out output\crypto\run
```

Writes `CRYPTO_RANKING.json` + `.md` + `hits/*`. Ranking identifies systems (dw_stub, AES-NI, Themida-class empty `.text`, ChaCha, UPX, …). Auto-solve promotes only validated transforms (`decrypted=true`).

Also: `analyze` · `links` · `ir` · `lift` · `classify` · `mcp` · `extract`  
`debug` is optional live host — **not** required for crypto/crack.

## IDA-like session (modules + flows + entry emu)

```bat
street session TARGET.exe --out output\session\run
```

Writes:

```
modules/AutoDumper.exe/pseudocode/*.c   IR, disasm
modules/KERNEL32.dll/                   separate DLL card + externs.c
modules/WININET.dll/                    …
flows/enc_000_<system>.json + _stub.c   encryption flow per ranked system
ENTRY_EMU.json                          micro-emu from EP
SESSION.json / SESSION.md
```

Gaps are written as `status: gap`, never silent.

## Kernel

Source: `kernel/StreetKernel.c` (from Street-v2_decryptor). IOCTL `READ_VIRTUAL` is CR3 walk + physical read.  
If `\\.\StreetKernel` is closed, the debugger uses `ReadProcessMemory`. That is the honest fallback.

## What x64dbg has vs what Street hosts

| x64dbg | Street (this tree) |
|--------|-------------------|
| TitanEngine debug loop | Own `DEBUG_PROCESS` loop in `street-debug` |
| Zydis CPU view | iced-x86 CPU panel |
| dump / regs / log | dump / regs / log in the same exe |
| plugins `.dp64` | optional `street_x64dbg.dll` *and* built-in menus |
| no decompiler | native C + IR |
| no auto URL harvest | `street links` |
| no kernel RPM | StreetKernel.sys optional |
| manual dump of injected pages | `street live-dump` — VA scan, flags private+exec, captures shellcode + driver delta |
| Scylla IAT | PE import parse + dump path (Python/C++ siblings) |

## Honesty

`CRITICAL.md`: C is pseudocode. Kernel hide/DKOM lives in the `.c` file; the host does not call `HIDE_SELF` on debug start. `decrypted` still requires a cipher or a proven runtime dump.

Sources consulted (not copied as IDA): x64dbg-development engine surface, reagent evidence packets, Street-v2_decryptor kernel + dump/OEP guard.
