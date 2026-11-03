# STREET-tool — Java decrypt (Sydney)

Saved from `dados1/STREET-tool` **without** the 1 GiB `github/` clones and without `tools/*.jar` / JDK.

## What decrypts Java here

**`SFsociety-decryptor/`** — Python JAR unpack + **Zelix Klassmaster 21** string recovery + Sydney native blob XOR.

```bat
python sfsociety.py path\to\file.jar -o out
python sfsociety.py --crack
```

Pipeline that was used on disk:

1. Unpack JAR → `inventory.csv`
2. Detect `ZKM21.0.0`
3. Recover 7-xor key from `<clinit>` → `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`
4. XOR decrypt resource blob → ELF `.so` / `sydney_loader.dll`
5. `java-deobfuscator` + `deobfuscator-config.yml` (109 strings) → CFR/Vineflower
6. Leftover ~8.6 MB still **AES inside native** (needs JNI_OnLoad / JDK 21)

Cloned reference tools (not in this git; listed in `github-tools.txt`):
`java-deobfuscator`, Diobf, threadtear, poke, Recaf, CFR, Procyon, Vineflower, BCV, …

## Mod that was analyzed

**Sydney 26.0** — Fabric utility client (anarchy combat/visuals).

| Field | Value |
|-------|--------|
| Mod id | `sydney` |
| Version | `26.0` |
| MC | `26.1.2` (depends `fabricloader >= 0.18.4`) |
| Authors | Aidan, zoom |
| Site | https://www.sydneyclient.net/ |
| Entry | `net.sydneyclient.loader.entrypoints.FabricEntryPoint` |

Evidence: `unpacked-meta/fabric.mod.json`, decompiled tree under original `out/vineflower/net/sydneyclient/…`.

Auth after native load: `%USERPROFILE%\.sydney\authorization.bin` — see `out-docs/AUTH_SYSTEM.md`.

## Docs kept

| File | Content |
|------|---------|
| `out-docs/CRACK_REPORT.md` | what SFsociety vs Diobf/jdo/threadtear did on this JAR |
| `out-docs/AUTH_SYSTEM.md` | boot order, MessageBox gate, Frida probes |
| `out-docs/inventory.csv` | class inventory |
| `SOURCES_COMPARE.md` | (inside SFsociety-decryptor) tool matrix |
| `tools-README.md` | how they invoked deobfuscator.jar + CFR |

## Not copied

- `github/` clones (~1 GiB)
- Temurin JDK + deobfuscator.jar / Recaf / threadtear JARs
- `target.jar` sample
- full `out/vineflower` / `out/cfr-deobf` trees (huge); reports above are enough
