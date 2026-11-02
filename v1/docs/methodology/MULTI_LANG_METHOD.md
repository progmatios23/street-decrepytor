# Multi-language methodology

## Why prior mono-tool flows failed

| Ecosystem | Typical prior approach | Failure mode |
|-----------|------------------------|--------------|
| .NET | One de4dot profile for all | Misses DNGuard HVM / Agile runtime decrypt |
| Native C++ | Signature DB + fixed OEP | Packer rebuilds kill AOBs next day |
| Rust/Tauri | Treat as “C++ with odd names” | Miss resource/brotli UI, command hash dispatch |
| Python freeze | Only PyInstaller TOC | Miss Nuitka/py2exe/custom loaders |
| Java | String regex deobf | Miss constant decryption at clinit |
| Go | strip + strings | Miss pclntab recovery path |
| Mixed C++/CLI | IL only or native only | Half the program invisible |

Street-decrepytor forces **classify first**, then **engine**, then **dynamic confirmation**.

## Shared stages (all languages)

1. Artifact identity (hash, size, format)
2. Entropy map (where ciphertext / packer shells live)
3. String + marker harvest (hints, not verdicts)
4. Protector candidates (behavioral + weak names)
5. Multi-build carve (embedded PE/JAR/layers)
6. Language deobf plan + offline heuristics
7. Optional live intercept / dump

## Language-specific levers

### C# / .NET
- CLR directory presence → route here
- Marker scan: ConfuserEx, SmartAssembly, DNGuard, Agile.NET, Obfuscar, Reactor, Babel, Eazfuscator
- Prefer **post-cctor dump** over static IL when anti-tamper present
- String encryption: emulate decryptor or hook `Encoding.GetString`

### Java
- JAR class inventory
- High-entropy names + decryptor methods → run offline emulator
- Export cleaned classes → CFR/Fernflower

### Python
- `.pyc` magic → version guess → decompile
- PyInstaller cookie / MEI → TOC extract → PYZ decrypt re-derive

### Go
- `Go build ID` / pclntab recovery (version-specific structures — re-derive)
- garble: treat like string decrypt + rename graph

### Rust
- panic paths + crate strings for orientation
- Tauri: asset table + frontend JS is first-class (not “noise”)
- Attach logic may be process spawn graphs, not VirtualAllocEx

### Native C/C++
- Junk density + opaque predicates via disassembly
- IAT starvation + virtual sections → packer shell playbook
- Themida/VMProtect → dynamic dump playbooks

### Mixed
- Run **both** CLR and native engines; merge reports

## Crypto recovery rule

**Never** ship a single global XOR key as the answer.  
Record *shapes* (imm64 pools, pxor lanes, AES-NI), then recover keys per function via emulation or API intercept (`BCryptDecrypt`, managed decryptors, etc.).

## Speed vs prior stacks

| Prior | Street |
|-------|--------|
| Separate scripts per sample in Temp\opencode | One `analyze` invocation |
| Docs drift (8 vs 52 gates) | Machine-verified gate table |
| Signature-only packer ID | Entropy + sections + markers + dynamic |
| Inject folklore | Architecture evidence + missing-child detection |
