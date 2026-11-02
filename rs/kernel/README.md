# StreetKernel.sys

Ring-0 companion compiled with VS + WDK (x64 Release). Same process `street.exe` talks to it via `\\.\StreetKernel`.

IOCTL (see `StreetKernel.c`):

| Code | Job |
|------|-----|
| 0x801 GET_EVENT | spawn / net MZ / RWX |
| 0x802 SET_TARGET | image-name filter |
| 0x803 FORCE_DUMP | |
| 0x804 GET_PAYLOAD | |
| 0x806 READ_VIRTUAL | CR3 walk + physical read (no OpenProcess) |

If the driver is not loaded, the debugger uses `ReadProcessMemory`. That is not a failure — kernel is the fallback when usermode RPM is starved.

Install (testsigning):

```
bcdedit /set testsigning on
sc create StreetKernel type= kernel start= demand binPath= C:\path\StreetKernel.sys
sc start StreetKernel
```
