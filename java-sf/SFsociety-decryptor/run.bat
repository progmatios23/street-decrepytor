@echo off
title SFsociety-decryptor
cd /d "%~dp0"
if "%~1"=="" (
  python sfsociety.py --crack
) else (
  python sfsociety.py %*
)
echo.
pause
