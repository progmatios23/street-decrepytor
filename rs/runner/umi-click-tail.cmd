@echo off
title Street — Umi events (live)
echo Warte auf EVENTS.jsonl ...
powershell -NoProfile -Command "$root='D:\Street-decrepytor-rs\output\pipeline\umi-ui'; $deadline=(Get-Date).AddMinutes(5); $f=$null; while(-not $f -and (Get-Date) -lt $deadline){ $f=Get-ChildItem $root -Recurse -Filter EVENTS.jsonl -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1; if(-not $f){ Start-Sleep 1 } }; if(-not $f){ 'keine events'; exit 1 }; 'tail '+$f.FullName; Get-Content -LiteralPath $f.FullName -Wait -Tail 40"
pause
