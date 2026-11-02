@echo off
setlocal
rem Static runner. Disk stages only. No debugger, no auth rewrite.
set "S=D:\Street-decrepytor-rs\target\release\street.exe"
if "%~1"=="" (
  echo usage: street-pipeline.bat ^<exe-or-dll^> [out-dir]
  exit /b 1
)
set "T=%~1"
set "O=%~2"
if "%O%"=="" set "O=D:\Street-decrepytor-rs\output\pipeline\%~n1"
"%S%" pipeline "%T%" --out "%O%"
if errorlevel 1 exit /b 1
echo PIPELINE %O%\PIPELINE.md
endlocal
