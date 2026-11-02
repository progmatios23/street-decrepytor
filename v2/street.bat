@echo off
cd /d "%~dp0"
set PYTHONPATH=%CD%;%CD%\..
python -m street_v2 %*
