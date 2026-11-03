# SFsociety-decryptor

Universal JAR unpack/dump + Sydney-loader (ZKM 21) decrypt.

## Run

```bat
run.bat
```

or any JAR:

```bat
python sfsociety.py C:\path\to\file.jar -o D:\STREET-tool\out
```

Needs Python 3.10+. `crack.py` uses the stdlib plus the local `jvm_lite` emulator.

```bat
python sfsociety.py --crack
```

Compares Diobf / java-deobfuscator / threadtear / poke / c2j against this loader and emulates ZKM 7-xor + native XOR. Inner AES leftover still needs Linux+JDK21 `JNI_OnLoad`.

## What it does

1. Unpacks the JAR (universal).
2. Dumps `inventory.csv`.
3. Detects Zelix Klassmaster 21 (`ZKM21.0.0`).
4. Recovers 7-xor `<clinit>` strings.
5. Decrypts the Sydney native blob with the recovered repeating-XOR key.
6. Writes `LOADER_REPORT.md` + `analysis.json` + `out/natives/*`.

## This target (`D:\STREET-tool\target.jar`)

Fabric client **Sydney 26.0** for Minecraft 26.1.2.

- Stub classes under `net.sydneyclient.loader.*`
- Encrypted resource `sydney$e5f314a7fc11534119712ea1` (~13.9 MB)
- XOR key `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO` (from ZKM 7-xor on `sydney$d80eeccfcac2600d61a77f3e`)
- ELF64 x86_64 `.so` at blob offset 19 after XOR
- Native methods still hold inner class bytes (`getResource` / `getClassBytes`)

Indy/ZKM `a(II)` names need `github/deobfuscator` + `deobfuscator-config.yml` on JDK 17+.
