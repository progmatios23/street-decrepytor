# HANDOFF — UMI Injector Deofuscation (emulador unicorn)

Gerado em: 2026-08-20T06:24:07.288346

## 1. Constantes criticas do emulador (emul_injector.py)

- `IMG_BASE` = 0x7FF732E70000
- `VALIDATE_FN` = IMG_BASE + 0x1FFDF9
- `INJECT_FN` = IMG_BASE + 0x308858  # real call target from main (doc 0x307858 was off-by)
- `ENTRY` = IMG_BASE + 0x4713
- `EARLY_CMP_JNE` = IMG_BASE + 0x44F6   # jne that early-exits when argv/ctx empty
- `FORCE_CONTINUE_AT` = IMG_BASE + 0x4576
- `STUB_BASE` = 0x0000030000000000
- `STUB_STRIDE` = 0x100
- `STACK_BASE` = 0x0000010000000000
- `STACK_SIZE` = 0x00400000
- `FAKE_MOD_BASE` = 0x0000050000000000
- `PEB_BASE` = 0x0000020000000000
- `TEB_BASE` = 0x0000020000010000
- `FakeHeap` = class FakeHeap:

Patches aplicados no boot do emulador:
- entry `0x74713` (skip prologo CRT) + `emu_start(ENTRY,...)`
- export limit 900 -> 4096 (RtlEnterCriticalSection faltava)
- CriticalSection stubs (RtlEnter/Leave/TryEnter + variantes)
- roteamento INT3 direto (handle_api + set RAX + pop ret + set RIP)
- FETCH-STUB retorna 1 (era 0)
- carregar TODOS os VADs (mem_map por regiao) — objeto heap 0x1f2b87310e0, export dir real, bcrypt real
- GetSystemDirectoryW escreve C:\\Windows\\System32; default Get* retorna objeto FakeHeap
- string-comparisons (_wcsicmp/RtlCompareUnicodeString/memcmp) forcadas a EQUAL (dump + return 0)
- GetHashInterface -> objeto interface 0x60 com slots de ponteiros hashfn_* (stubs)
- patched memset AVX check (0x7ff732ebab36 jb) -> forced SSE path (unicorn nao tem vinsertf128)
- CHECKPOINT pos-VALIDATE (0x7ff732e74748): log eax + forca EAX=0 (licenca valida) + seed config obj 0x40000001100 em [rsp+0x58]
- INJECT params dump (rcx/rdx/r8/r9 + [rcx] hexdump) no hit do INJECT fn
- CALL-IND trace ntdll@0x7ffd5aaa3397 + JMPRAX trace ntdll@0x7ffd5aaa9760
- runaway handler: TRACE 5000 entradas + TRANSICAO (low_start) + transfers (last 30) + regs

## 2. Stubs, exports e IAT

Stub names registrados (143):
```
  FlsAlloc, FlsGetValue, FlsSetValue, FlsFree, InitializeCriticalSectionEx, InitializeCriticalSection
  EnterCriticalSection, LeaveCriticalSection, DeleteCriticalSection, AreFileApisANSI, CompareStringEx, EnumSystemLocalesEx
  GetDateFormatEx, GetLocaleInfoEx, GetTimeFormatEx, GetUserDefaultLocaleName, IsValidLocaleName, LCMapStringEx
  LCIDToLocaleName, LocaleNameToLCID, SetConsoleTitleA, IsWindowVisible, BCryptGetProperty, GetModuleHandleA
  GetModuleHandleW, GetModuleHandleExW, LoadLibraryA, LoadLibraryW, LoadLibraryExW, FreeLibrary
  GetProcAddress, FatalExit, ExitProcess, TerminateProcess, ExitThread, RtlAllocateHeap
  RtlFreeHeap, HeapAlloc, HeapFree, HeapReAlloc, HeapSize, GetProcessHeap
  malloc, calloc, realloc, free, memcpy, memmove
  memset, strlen, wcslen, GetLastError, SetLastError, GetCurrentProcess
  GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, Sleep, SleepEx, GetTickCount
  GetTickCount64, QueryPerformanceCounter, CloseHandle, DuplicateHandle, GetStdHandle, WriteConsoleA
  WriteConsoleW, GetConsoleMode, MultiByteToWideChar, WideCharToMultiByte, GetModuleFileNameA, GetModuleFileNameW
  MessageBoxA, MessageBoxW, MessageBoxTimeoutA, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW
  Process32First, Process32Next, Thread32First, Thread32Next, Module32FirstW, Module32NextW
  OpenProcess, OpenThread, VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx
  VirtualProtect, VirtualProtectEx, ReadProcessMemory, WriteProcessMemory, CreateRemoteThread, CreateRemoteThreadEx
  QueueUserAPC, NtQueueApcThread, NtQueueApcThreadEx, NtCreateThreadEx, RtlCreateUserThread, NtAllocateVirtualMemory
  NtProtectVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory, NtMapViewOfSection, NtCreateSection, NtUnmapViewOfSection
  NtOpenProcess, NtClose, SuspendThread, ResumeThread, GetThreadContext, SetThreadContext
  NtGetContextThread, NtSetContextThread, WaitForSingleObject, WaitForSingleObjectEx, GetExitCodeThread, CreateFileA
  CreateFileW, ReadFile, WriteFile, GetFileSize, CreateFileMappingW, MapViewOfFile
  UnmapViewOfFile, EnumProcessModules, EnumProcessModulesEx, GetModuleBaseNameA, GetModuleBaseNameW, K32EnumProcessModules
  K32GetModuleBaseNameW, IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, OutputDebugStringA, OutputDebugStringW
  GetSystemTimeAsFileTime, GetLocalTime, RtlInitUnicodeString, LdrLoadDll, LdrGetProcedureAddress
```

## 3. Ultima execucao (run41)


Log completo salvo em: output/emu_injector/emu_run41.log

## 4. Analise do crash atual (bloqueio)

### Fluxo real capturado (funciona)
```
main (0x7ff732e74713) -> VALIDATE (0x7ff73306fdf9):
  RtlAllocateHeap(0x188) -> obj 0x40000001100 (memset 0)
  RtlEnterCriticalSection(cs@bcrypt+0x1640)
  _wcsicmp('bcryptprimitives.dll' vs 'bcryptprimitives.dll') -> EQUAL(forced)
  GetProcAddress('GetHashInterface') -> stub
  GetHashInterface -> interface 0x40000001290 (slots hashfn_*)
  RtlLeaveCriticalSection
  retorna eax=c00000bb (STATUS_NOT_SUPPORTED) — math OLLVM, sem API calls no meio
main@0x74748: test eax,eax; jns -> FORCADO EAX=0 -> branch do INJECT
main seeds [rsp+0x58] = 0x40000001100 (config obj)
main: call INJECT (0x7ff733178858)  <- MILESTONE ATINGIDO
  INJECT params: rcx=0x40000001100 (config) rdx=0x7ff732ecab58 r8=0x100003ff050 r9=4
  RtlAllocateHeap(0x1127) -> 0x400000012f0  (payload buffer! 4391 bytes)
  RtlAllocateHeap(0x0) -> 0x40000002420
  BCryptGetProperty x3 (setup hash)
  ...blocos OLLVM do corpo do INJECT (537 enderecos, paginas 0x7ff733048000-0x7ff7331b6000)...
  ret do INJECT cai em ntdll (stack manipulada pelo OLLVM)
  ntdll@0x7ffd5aaa3397: call [rip+0x186ab] -> 0x9a00007ffd5aaa97  <- ponteiro CORROMPIDO
  ntdll@0x7ffd5aaa9760: jmp rax com rax=0  <- tail-call helper real, NAO nosso trampoline
  -> fetch 0xfa6/0x1000 UNMAPPED -> RUNWAY (low walk de 0xbbf..0xfa7 em passo 2)
```

### Diagnostico

1. O VALIDATE retorna c00000bb por math OLLVM pura (entre GetHashInterface e LeaveCS
   nao ha NENHUMA API call) — ele provavelmente checa se a interface de hash tem
   um valor/assinatura esperado que nosso fake nao tem.
2. O INJECT fn EXECUTA (milestone 1!) — aloca payload 0x1127, faz setup hash
   (BCryptGetProperty x3), e depois crasha quando o retorno cai no ntdll real e
   um call-indireto via IAT do ntdll aponta para 0x9a00007ffd5aaa97 (ponteiro
   corrompido) e o tail-call jmp rax com rax=0 vai para o low range.
3. O ntdll real esta mapeado com codigo real, mas os IAT internos do ntdll
   (call [rip+...]) apontam para enderecos de outras DLLs (kernel32/kernelbase)
   que estao no range de sistema — se nao estao reescritos com trampolines,
   o codigo real roda e chama helpers reais que fazem jmp rax.

### O que esta FALTANDO para chegar nas APIs de injecao (CreateRemoteThread/APC)

A. Fazer o VALIDATE retornar 0 NATURALMENTE (sem force):
   - descobrir o que o VALIDATE espera da interface GetHashInterface (assinatura/versao/campos) e preencher o objeto fake com esses campos
   - OU: patch no retorno do VALIDATE (0x7ff73306fdf9 thunk) para ret 0 direto
     em vez de force no main (mais robusto: nao precisa do seed do config)
B. Corrigir o ponteiro corrompido 0x9a00007ffd5aaa97 no IAT do ntdll:
   - dump do IAT interno do ntdll (slots call [rip+...]) e reescrever TODOS
     com trampolines para stubs (como fazemos com exports live)
   - ou interceptar o call-indireto e redirecionar para stub pelo endereco alvo
C. Rastrear o corpo real do INJECT ate as APIs de injecao:
   - o INJECT ja aloca payload (0x1127) — proximo passo dele deve ser decript
     (BCrypt*) + injecao — as APIs de injecao estao nas paginas 0x7ff733180000+
   - procurar CreateRemoteThread/NtCreateThreadEx/QueueUserAPC nas paginas altas
     do .text X (0x7ff733048000-0x7ff7331b6000) via grep de hashes/IAT

## 5. TODOs abertos

[ ] Guard no dispatcher (thunk 0x7ff732eba260 jmp-rax) — implementado mas NAO disparou (crash nao passa por ele)
[ ] Dump da lista [rdi+0x38] no call 0x7ff732e96160 (walker) — nao necessario ate novo crash
[ ] Fazer VALIDATE retornar 0 natural (patch no thunk 0x7ff73306fdf9 ou preencher interface real)
[ ] Corrigir IAT interno do ntdll (0x7ffd5aaa3397 call [rip+0x186ab] -> 0x9a00007ffd5aaa97 corrompido)
[ ] Rastrear corpo do INJECT ate APIs de injecao (CreateRemoteThread/APC/NtCreateThreadEx)
[ ] Registrar a tecnica real de injecao (comparar com nossa reconstrucao APC LoadLibraryW)
[ ] Atualizar EMU_PROGRESSO.md + EMU_REPORT com os achados do run41
[ ] Runaway handler: print TRANSICAO finalizado; verificar se ha novos crashes apos fix do IAT

## 6. Inventario de arquivos do projeto

- `docs\ANALISE_UMI_DUMPP.md` (6332 bytes)
- `docs\DOCUMENTACAO.md` (12140 bytes)
- `docs\FLUXO_ROBLOX.md` (7094 bytes)
- `docs\INJECTOR_RE.md` (5796 bytes)
- `docs\NOSSO_BACKEND.md` (5043 bytes)
- `docs\RELATORIO_UMI.md` (8207 bytes)
- `docs\TESTES.md` (10877 bytes)
- `mock_roblox.obj` (7512 bytes)
- `src\injector.c` (34966 bytes)
- `src\thin.c` (16455 bytes)
- `src\umi_core.cpp` (63126 bytes)
- `src\umi_loader.c` (21046 bytes)
- `src\umi_module.cpp` (25665 bytes)
- `tools\clean_agent.py` (13917 bytes)
- `tools\deobf_pe.py` (24812 bytes)
- `tools\emul_injector.py` (53990 bytes)
- `tools\emul_vm2.py` (5682 bytes)
- `tools\find_sched_fn.py` (5990 bytes)
- `tools\handoff_snapshot.py` (13034 bytes)
- `tools\hash_crack.py` (6968 bytes)
- `tools\hook_bootstrap.py` (12236 bytes)
- `tools\job_inject.py` (6157 bytes)
- `tools\job_inject2.py` (6677 bytes)
- `tools\job_redirect.py` (5297 bytes)
- `tools\job_step_slot.py` (5693 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\hooks\hooking.hpp` (22470 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\capstone.lib` (5130 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imconfig.h` (8102 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui.cpp` (846442 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui.h` (304242 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_demo.cpp` (406982 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_draw.cpp` (211857 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_impl_dx9.cpp` (22501 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_impl_win32.cpp` (46965 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_internal.h` (214897 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_tables.cpp` (211623 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imgui_widgets.cpp` (401208 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imstb_rectpack.h` (20540 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imstb_textedit.h` (54923 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\imgui\imstb_truetype.h` (192489 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\libcurl.lib` (1875826 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\include\MinHook.h` (7503 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\MinHook.h` (7499 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\minhook.lib` (517200 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\minhook3.lib` (273826 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\minhookback2.lib` (503408 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\minhookdd.lib` (39284 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\src\buffer.c` (9809 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\src\hde\hde32.c` (9383 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\src\hde\hde64.c` (9572 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\src\hook.c` (25043 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\includes\minhook\src\trampoline.c` (10574 bytes)
- `tools\re-kit-2.0-master\re-kit-2.0\re-kit\menu\menu.hpp` (11779 bytes)
- `tools\re-kit-2.0-master.zip` (1905248 bytes)
- `tools\runtime_unpack.py` (7083 bytes)
- `tools\spawn_dump.py` (20782 bytes)
- `tools\step_hunt.py` (5622 bytes)
- `tools\themida-unmutate-main\docs\themida-mutation-recon24.pdf` (1254187 bytes)
- `tools\themida-unmutate-main\LICENSE` (35149 bytes)
- `tools\themida-unmutate-main\poetry.lock` (19420 bytes)
- `tools\themida-unmutate-main\themida_unmutate\miasm_utils.py` (7218 bytes)
- `tools\themida-unmutate-main\themida_unmutate\rebuilding.py` (9196 bytes)
- `tools\themida-unmutate-main\themida_unmutate\symbolic_execution\x86\__init__.py` (30540 bytes)
- `tools\themida-unmutate-main.zip` (1133937 bytes)
- `tools\Themidie2-master\.gitignore` (6223 bytes)
- `tools\Themidie2-master\[Themida] Themide\[Themida] Themide.vcxproj` (8609 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\buffer.c` (9814 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\hde\hde32.c` (9318 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\hde\hde64.c` (9459 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\hook.c` (26117 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\MinHook.h` (7530 bytes)
- `tools\Themidie2-master\[Themida] Themide\Libraries\minhook\trampoline.c` (10631 bytes)
- `tools\Themidie2-master\[Themida] Themide\Source\Hooks\Hooks.cpp` (17775 bytes)
- `tools\Themidie2-master\[Themida] Themide\Source\ntdll.h` (250959 bytes)
- `tools\Themidie2-master\ThemidiePlugin\jansson_x64.lib` (15226 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\_dbgfunctions.h` (9883 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\_plugins.h` (9406 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\bridgegraph.h` (6008 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\bridgemain.h` (48809 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\jansson\jansson.h` (11532 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\jansson\jansson_x64.a` (50726 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\jansson\jansson_x86.a` (50588 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\jansson\jansson_x86.lib` (15550 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\x32bridge.lib` (53804 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Libraries\pluginsdk\x32dbg.lib` (91134 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Themidie_X64DBG_PLUGIN.ico` (72090 bytes)
- `tools\Themidie2-master\ThemidiePlugin\Themidie_X64DBG_PLUGIN.png` (64376 bytes)
- `tools\Themidie2-master\ThemidiePlugin\ThemidiePlugin.vcxproj` (8590 bytes)
- `tools\Themidie2-master\ThemidiePlugin\x64bridge.lib` (52634 bytes)
- `tools\Themidie2-master\ThemidiePlugin\x64dbg.lib` (117568 bytes)
- `tools\Themidie2-master.zip` (318525 bytes)
- `tools\umi_disasm.py` (6809 bytes)
- `tools\umi_disasm2.py` (5656 bytes)
- `tools\umi_recon.py` (6283 bytes)
- `tools\universal_analyzer.py` (10736 bytes)
- `tools\universal_dump.py` (10573 bytes)
- `tools\unpack_injector2.py` (8297 bytes)
- `tools\vm_universal.py` (5834 bytes)
- `ui\_app\immutable\assets\0.CLj10_gw.css` (47226 bytes)
- `ui\_app\immutable\chunks\BcJhZgNS.js` (52656 bytes)
- `ui\_app\immutable\chunks\BPxjBoUe.js` (26708 bytes)
- `ui\_app\immutable\nodes\2.BmRCqKjo.js` (545347 bytes)
- `ui\intro.mp3` (111732 bytes)
- `ui\profile.png` (14243 bytes)
- `ui\ui.zip` (310046 bytes)
- `umi_ui\_app_immutable_assets_0.CLj10_gw.css` (47226 bytes)
- `umi_ui\_app_immutable_chunks_BcJhZgNS.js` (52656 bytes)
- `umi_ui\_app_immutable_chunks_BPxjBoUe.js` (26708 bytes)
- `umi_ui\_app_immutable_nodes_2.BmRCqKjo.js` (544409 bytes)
- `umi_ui\intro.mp3` (111732 bytes)
- `umi_ui\profile.png` (14243 bytes)
- `umi_ui\umi_ui.zip` (308803 bytes)

### VADs do dump (diretorio source)
- `vad_000000007ffe0000_sz1000.bin` (4096 bytes)
- `vad_000000007ffed000_sz1000.bin` (4096 bytes)
- `vad_000000943d68e000_sz9000.bin` (36864 bytes)
- `vad_000000943d8fc000_sz4000.bin` (16384 bytes)
- `vad_000000943d9fe000_sz2000.bin` (8192 bytes)
- `vad_000000943dafe000_sz2000.bin` (8192 bytes)
- `vad_000000943dbff000_sz1000.bin` (4096 bytes)
- `vad_000001f2b8630000_sz10000.bin` (65536 bytes)
- `vad_000001f2b8640000_sz2000.bin` (8192 bytes)
- `vad_000001f2b8650000_sz1d000.bin` (118784 bytes)
- `vad_000001f2b8670000_sz4000.bin` (16384 bytes)
- `vad_000001f2b8680000_sz1000.bin` (4096 bytes)
- `vad_000001f2b8690000_sz2000.bin` (8192 bytes)
- `vad_000001f2b86a0000_sz2000.bin` (8192 bytes)
- `vad_000001f2b86b0000_sz1000.bin` (4096 bytes)
- `vad_000001f2b86c0000_sz2000.bin` (8192 bytes)
- `vad_000001f2b8700000_sz4000.bin` (16384 bytes)
- `vad_000001f2b8710000_sz1000_X.bin` (4096 bytes)
- `vad_000001f2b8720000_sz1b000.bin` (110592 bytes)
- `vad_000001f2b8811000_sz1000.bin` (4096 bytes)
- `vad_000001f2b8820000_szc9000.bin` (823296 bytes)
- `vad_000001f2b88f0000_sz13000.bin` (77824 bytes)
- `vad_000001f2b8af0000_sz181000.bin` (1576960 bytes)
- `vad_000001f2b8c80000_szab000.bin` (700416 bytes)
- `vad_000001f2ba090000_sz1000.bin` (4096 bytes)
- `vad_000001f2ba190000_sz9000.bin` (36864 bytes)
- `vad_000001f2ba1a0000_szac000.bin` (704512 bytes)
- `vad_00007ff4f7f60000_sz5000.bin` (20480 bytes)
- `vad_00007ff5fa080000_sz1000.bin` (4096 bytes)
- `vad_00007ff5fa090000_sz1000.bin` (4096 bytes)
- `vad_00007ff5fa0a0000_sz23000.bin` (143360 bytes)
- `vad_00007ff732e70000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ff732e71000_sz4c000_X.bin` (311296 bytes)
- `vad_00007ff732ebd000_sz16000.bin` (90112 bytes)
- `vad_00007ff732ed3000_sz3000.bin` (12288 bytes)
- `vad_00007ff732ed6000_sz4000.bin` (16384 bytes)
- `vad_00007ff732eda000_sz37000_X.bin` (225280 bytes)
- `vad_00007ff732f11000_sz6000.bin` (24576 bytes)
- `vad_00007ff732f17000_sz6f1000_X.bin` (7278592 bytes)
- `vad_00007ff733608000_sz1000.bin` (4096 bytes)
- `vad_00007ff733609000_szc33000_X.bin` (12791808 bytes)
- `vad_00007ff73423c000_sz2000.bin` (8192 bytes)
- `vad_00007ffd5a620000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5a621000_sza5000_X.bin` (675840 bytes)
- `vad_00007ffd5a6c6000_sz52000.bin` (335872 bytes)
- `vad_00007ffd5a718000_sz5000.bin` (20480 bytes)
- `vad_00007ffd5a71d000_sz1d000.bin` (118784 bytes)
- `vad_00007ffd5a7c0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5a7c1000_sz54000_X.bin` (344064 bytes)
- `vad_00007ffd5a815000_sz3c000.bin` (245760 bytes)
- `vad_00007ffd5a851000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5a852000_sz3000.bin` (12288 bytes)
- `vad_00007ffd5a855000_sz8000.bin` (32768 bytes)
- `vad_00007ffd5a910000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5a911000_szb000_X.bin` (45056 bytes)
- `vad_00007ffd5a91c000_szf000.bin` (61440 bytes)
- `vad_00007ffd5a92b000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5a92c000_sz6000.bin` (24576 bytes)
- `vad_00007ffd5aaa0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5aaa1000_sz1a000_X.bin` (106496 bytes)
- `vad_00007ffd5aabb000_sz6000.bin` (24576 bytes)
- `vad_00007ffd5aac1000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5aac2000_sz5000.bin` (20480 bytes)
- `vad_00007ffd5aad0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5aad1000_szb4000_X.bin` (737280 bytes)
- `vad_00007ffd5ab85000_sz3a000.bin` (237568 bytes)
- `vad_00007ffd5abbf000_sz3000.bin` (12288 bytes)
- `vad_00007ffd5abc2000_sze000.bin` (57344 bytes)
- `vad_00007ffd5ac20000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5ac21000_sz64000_X.bin` (409600 bytes)
- `vad_00007ffd5ac85000_sz16000.bin` (90112 bytes)
- `vad_00007ffd5ac9b000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5ac9c000_sz6000.bin` (24576 bytes)
- `vad_00007ffd5acb0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5acb1000_sz132000_X.bin` (1253376 bytes)
- `vad_00007ffd5ade3000_sz183000.bin` (1585152 bytes)
- `vad_00007ffd5af66000_sz5000.bin` (20480 bytes)
- `vad_00007ffd5af6b000_sz3c000.bin` (245760 bytes)
- `vad_00007ffd5b0e0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5b0e1000_sz81000_X.bin` (528384 bytes)
- `vad_00007ffd5b162000_sz35000.bin` (217088 bytes)
- `vad_00007ffd5b197000_sz2000.bin` (8192 bytes)
- `vad_00007ffd5b199000_sz9000.bin` (36864 bytes)
- `vad_00007ffd5b1b0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5b1b1000_sz1e000_X.bin` (122880 bytes)
- `vad_00007ffd5b1cf000_sz6000.bin` (24576 bytes)
- `vad_00007ffd5b1d5000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5b1d6000_sz9000.bin` (36864 bytes)
- `vad_00007ffd5b4e0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5b4e1000_szf000_X.bin` (61440 bytes)
- `vad_00007ffd5b4f0000_sz14000.bin` (81920 bytes)
- `vad_00007ffd5b504000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5b505000_sz6000.bin` (24576 bytes)
- `vad_00007ffd5ba80000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5ba81000_sz8e000_X.bin` (581632 bytes)
- `vad_00007ffd5bb0f000_sz21000.bin` (135168 bytes)
- `vad_00007ffd5bb30000_sz2000.bin` (8192 bytes)
- `vad_00007ffd5bb32000_szeb000.bin` (962560 bytes)
- `vad_00007ffd5cfb0000_sz1000_PE.bin` (4096 bytes)
- `vad_00007ffd5cfb1000_sz11c000_X.bin` (1163264 bytes)
- `vad_00007ffd5d0cd000_sz49000.bin` (299008 bytes)
- `vad_00007ffd5d116000_sz1000.bin` (4096 bytes)
- `vad_00007ffd5d117000_sz2000.bin` (8192 bytes)
- `vad_00007ffd5d119000_sz9000.bin` (36864 bytes)
- `vad_00007ffd5d122000_sz86000.bin` (548864 bytes)
- `vad_00007ffd5d1b0000_sz1000_X.bin` (4096 bytes)
- `vad_00007ffd5d1b1000_sz1000_X.bin` (4096 bytes)

## 7. Comandos uteis

```powershell
# rodar o emulador (entry 0x74713, forcando licenca valida)
python tools/emul_injector.py > $env:TEMP/opencode/emu_run.log 2>&1
# ver resumo
Get-Content $env:TEMP/opencode/emu_run.log | Select-String -Pattern 'CHECKPOINT|hit INJECT|stopped|milestones|coverage'
# compilar nossa reconstrucao (build separado)
cmd /c build.bat   # na pasta build/
# desassemblar blocos do .text X
python -c "from capstone import *; md=Cs(CS_ARCH_X86,CS_MODE_64); data=open(r'C:/claude/grok-persona/Street-decrepytor/output/dumps/umi_injector/spawn/vad/vad_00007ff732f17000_sz6f1000_X.bin','rb').read(); [print(f'{i.address:#x}: {i.mnemonic} {i.op_str}') for i in md.disasm(data[addr-0x7ff732f17000:][:0x100], addr)]"
```

## 8. Dicas de continuacao — proximos passos concretos

1. **Patch direto no VALIDATE**: em vez de forcar EAX=0 no main, patchar o thunk
   do VALIDATE (0x7ff73306fdf9: pop rsi; push rbx; pushfq; movabs rbx,...) para
   `xor eax,eax; ret` — assim o main recebe 0 naturalmente, o config obj e'
   preenchido de verdade, e o INJECT recebe dados reais.
2. **Interceptar call-indireto do ntdll**: hook no on_code para 0x7ffd5aaa3397,
   ler o slot [0x7ffd5abfc049], e se apontar para range de sistema, redirecionar
   para o stub do export mais proximo (ou logar e pular).
3. **Procurar APIs de injecao no .text X**: grep nas paginas 0x7ff733180000+ por
   padroes de IAT (call [rip+...]) ou hashes de nomes (movabs de hash) e
   desassemblar os blocos candidatos.
4. **Comparar com nossa reconstrucao**: nossa build usa APC LoadLibraryW; se o UMI
   real usar outra tecnica (ex: NtCreateThreadEx + WriteProcessMemory), atualizar
   docs/NOSSO_BACKEND.md e a implementacao em build/.
