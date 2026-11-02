# tools/ — lab only, not the Street CLI

These scripts are **not** `street-decrepytor` commands. They are UMI injector lab helpers.

| File | Job | Decrypts packer? |
|------|-----|------------------|
| `emul_injector.py` | Unicorn-ish emu of injector | **no**. R-EMU7 still short-circuits before INJECT body |
| `run_frida_inject_trace.py` + `frida_inject_trace.js` | Live Frida on packed injector | **no**. Evidence for secmap inject |
| `stealth_frida_run.py` | Stealth attach | no |
| `msgbox_watch.py` | First-run MessageBox | no |

Truth for UMI inject: `output/handoff_deobf/STREET_UMI_TRUTH.md` (section map, not APC).

```bat
cd /d D:\Street-decrepytor
set PYTHONPATH=%CD%
python tools\emul_injector.py
python tools\run_frida_inject_trace.py
```
