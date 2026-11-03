@echo off
set JAVA=D:\STREET-tool\tools\jdk\bin\java.exe
set TOOLS=D:\STREET-tool\tools
"%JAVA%" -version
echo --- java-deobfuscator ZKM ---
"%JAVA%" -jar "%TOOLS%\deobfuscator.jar" --config "%~dp0deobfuscator-config.yml"
echo --- CFR loader classes ---
"%JAVA%" -jar "%TOOLS%\cfr-0.152.jar" D:\STREET-tool\out\unpacked\net\sydneyclient\loader --outputdir D:\STREET-tool\out\cfr
echo done
