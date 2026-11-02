# Audit — prior tools (opencode / cracked / ANALISTAR)

## Inventory (high value)

| Tool / path | Role | Integrate into Street? |
|-------------|------|------------------------|
| `opencode/krypton_tool` | packer/junk/antidebug/sigscan CLI | **Yes** — stages mirror + supersede |
| `opencode/ida-pro-junk-code-removal-master` | IDA junk pass | Optional IDA plugin bridge |
| `opencode/Magicmida*` / ANALISTAR Magicmida64 | Themida helper inject | Protector playbook interop |
| ANALISTAR `Themidie` | anti-anti-debug | `dynamic/antidebug` |
| ANALISTAR `Themida-Unpacker-for-.NET` | .NET Themida | csharp plan branch |
| `server_files/simd_decrypt_v2.py` | DLL string emu | crypto module |
| `server_files/decrypt_*.py` | batch decrypt | crypto + potassium |
| `server_files/patch_table.json` | 4206 IMM sites | label as strings not gates |
| `cracked/bin/dll_gates_sigs.json` | 52 auth gates | potassium.verify |
| `cracked/recrack.py` | re-apply gates | scripts/recrack_bridge |
| `cracked/bin/mock_api.py` + proxy | offline stack | out of band (product crack) |
| `cracked/bin/injector.py` | LoadLibrary | **Do not** treat as product path |
| `opencode/bootkit-v2-2` | EFI multi-game | **Out of scope** for Potassium |
| ANALISTAR `ida-pro-mcp` | IDA MCP | external; Street emits JSON for agents |
| ANALISTAR `x64DbgMCPServer` | debugger MCP | dynamic interop later |
| beta18 Hyperion SPEC | usermode survival | docs reference only |

## Accuracy ratings (docs)

| Document | Accuracy | Notes |
|----------|----------|-------|
| `cracked/AUDIT_FULL_2026-08-12.md` | **High** | Best single truth source |
| `cracked/TASK_POTASSIUM_HYPERION.md` | **High** | Clear DONE criteria |
| `cracked/DOCUMENTACAO_TECNICA.md` | **Med-High** | Strong mock/UI; gate count aged (8→52) |
| `opencode/RELATORIO_FINAL_POTASSIUM.md` | **Med** | Excellent batch/update RE; inject framing needs child nuance |
| `opencode/ATTACH_FLOW_REPORT.md` | **High** | Child spawn evidence |
| `ANALISTAR/docs/Potassium_analysis.md` | **High** | IDA attach/auth map |
| Random opencode `emul_run*.log` claims | **Low** | Session noise |

## Immediate improvements Street implements

1. Hash-labeled artifact discovery  
2. Gate verification with RVA→offset  
3. Explicit separation of patch_table vs gates  
4. Protector + junk + strings + deobf in one JSON  
5. Frida hook generation without absolute addresses  
6. Case study refuses inject-complete false positive  

## Still external (not reimplemented v0.1)

- Full unicorn PEB syscall emulator suite from opencode  
- Complete 4206-string offline decrypt at de4dot quality  
- Hyperion-aware inject PE recreation  
- GUI (CLI only by design)  
