@echo off
title Street — injector ao vivo
cd /d D:\Street-decrepytor-rs
echo.
echo Fluxo: classify + complete + pdata + observe sem debugger
echo Alvo: %APPDATA%\umi\bin\injector.exe
echo Out:  D:\Street-decrepytor-rs\output\pipeline\injector-live
echo Build: street.exe com read imediato do image. Sem MZ, unpacked fica false.
echo.
echo A sonda e a seccao virtual maior (.themida). Shannon ^>= 4 grava image.bin.
echo Uma segunda janela e o proprio injector. Nao feches esta.
echo.
call runner\street-observe.bat "%APPDATA%\umi\bin\injector.exe" "D:\Street-decrepytor-rs\output\pipeline\injector-live" 70
echo.
echo exit=%ERRORLEVEL%
echo.
if exist "D:\Street-decrepytor-rs\output\pipeline\injector-live\03-probe.json" type "D:\Street-decrepytor-rs\output\pipeline\injector-live\03-probe.json"
echo.
if exist "D:\Street-decrepytor-rs\output\pipeline\injector-live\PIPELINE.md" type "D:\Street-decrepytor-rs\output\pipeline\injector-live\PIPELINE.md"
echo.
echo Janela fica aberta. Repete com: runner\injector-live.cmd
pause
