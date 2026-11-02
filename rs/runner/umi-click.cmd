@echo off
title Street debugger — Umi (click the window)
cd /d "C:\Program Files\umi"
echo.
echo umi.exe is under the Street debugger. Click that window.
echo Trace runs 600 seconds.
echo Child processes (injector) are NOT in the debugger.
echo Events: D:\Street-decrepytor-rs\output\pipeline\umi-ui
echo.
"D:\Street-decrepytor-rs\target\release\street.exe" trace "C:\Program Files\umi\umi.exe" --seconds 600 --out "D:\Street-decrepytor-rs\output\pipeline\umi-ui" --categories process,file,memory,module,network,registry,ui
echo.
echo exit=%ERRORLEVEL%
echo Trace finished. Report is in the folder above.
pause
