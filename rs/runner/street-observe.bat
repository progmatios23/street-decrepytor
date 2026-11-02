@echo off
setlocal
rem No-debug observe after the static pipeline. Does not attach DEBUG_PROCESS.
rem Packed hosts only. Clear binaries skip the spawn.
set "S=D:\Street-decrepytor-rs\target\release\street.exe"
if "%~1"=="" (
  echo usage: street-observe.bat ^<exe^> [out-dir] [seconds]
  exit /b 1
)
set "T=%~1"
set "O=%~2"
if "%O%"=="" set "O=D:\Street-decrepytor-rs\output\pipeline\%~n1"
set "SEC=%~3"
if "%SEC%"=="" set "SEC=40"
"%S%" pipeline "%T%" --out "%O%" --observe --seconds %SEC% --elevate
if errorlevel 1 exit /b 1
echo PIPELINE %O%\PIPELINE.md
endlocal
