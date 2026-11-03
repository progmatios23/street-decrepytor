# SFsociety crack report

generated: 2026-09-03T02:02:00.791406+00:00
tool 1.0.0

## Source compare (ours vs cloned github)

| tool | ZKM | native | VM | on disk |
|---|---|---|---|---|
| SFsociety-decryptor (ours) | ZKM21 7-xor tableswitch + StaticInit port + jvm_lite a(II/III) | repeating-XOR ELF extract, leftover AES not broken | Python interpreter (no indy MH) | True |
| Diobf/Deobfuscator (narumi) | ComposedZelixTransformer, ZKMCipher, tested ZKM 22.0.3 | none | ASM transformers + optional sandbox | False |
| java-deobfuscator/deobfuscator | StringEncryptionTransformer + Enhanced via javavm | none | full Java VM (javavm) — best for indy | True |
| GraxCode/threadtear | StringObfuscationZKM + DESObfuscationZKM + AccessObfuscationZKM | none | Sandbox VM, reflection required | True |
| katana-project/poke | generic ProGuard-core normalize, not ZKM-specific | none | no | True |
| c2j-native-deobfuscator | no | JVMTI + Ghidra + CPU emu + mock JNI (native-obfuscator / j2cc) | CPU emulator | True |

## What we emulate

- Diobf `ZKMCipher.cipher2` = 7-xor tableswitch (proven: blob key `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`)
- java-deobfuscator enhanced `(II)/(III)Ljava/lang/String;` via `jvm_lite` (partial; ZKM junk stack)
- threadtear-style isolate of String calls — same interpreter
- c2j-style native unpack: XOR record 0 → ELF64 `JNI_OnLoad` AWS-LC

## Emulator statics

```json
{
  "classes": {
    "net/sydneyclient/loader/h": {
      "ok": false,
      "error": "TypeError: 'NoneType' object is not iterable"
    },
    "net/sydneyclient/loader/Natives": {
      "ok": false,
      "error": "IndexError: pop from empty list"
    },
    "net/sydneyclient/loader/sydney$15b1214126c9445e43e20cac": {
      "ok": true,
      "statics": {}
    },
    "net/sydneyclient/loader/sydney$64c685e4bf6aace73d87a9f6": {
      "ok": true,
      "statics": {
        "a": [
          "\u00fe\u00ff\u00db\u00db;\u001b\u00e3\u00c7\u00b4\u0010",
          "\u00eb(y!oDi,\u00e5m",
          "A\u00a5,\u0090\u00c5r<\u00eaO\u00b5"
        ],
        "b": [
          "None",
          "None",
          "0123456789"
        ],
        "sydney$08332c9a751e0498e97f7ae5": "0123456789"
      }
    },
    "net/sydneyclient/loader/sydney$7152c7b5eb6ae69b2c340550": {
      "ok": false,
      "error": "IndexError: pop from empty list"
    },
    "net/sydneyclient/loader/sydney$9a507a96730881c19defc24e": {
      "ok": true,
      "statics": {}
    },
    "net/sydneyclient/loader/sydney$d80eeccfcac2600d61a77f3e": {
      "ok": true,
      "statics": {
        "sydney$b7eddfb033b1edc0aa50c97f": {
          "bytes_len": 32,
          "head": "437162486e42724134514d423341736e456d66625047343258444d584430514f",
          "ascii": "CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
        }
      }
    },
    "net/sydneyclient/loader/sydney$f153d455a63a6a08821fbfce": {
      "ok": true,
      "statics": {}
    },
    "net/sydneyclient/loader/sydney$f9dc8891520f0d71c46c7b04": {
      "ok": false,
      "error": "VMError: invokedynamic at 0x8 stack=[<class 'int'>, <class 'int'>]"
    },
    "net/sydneyclient/loader/entrypoints/FabricEntryPoint": {
      "ok": true,
      "statics": {}
    },
    "net/sydneyclient/loader/resources/NativeResourcePack": {
      "ok": true,
      "statics": {}
    }
  },
  "strings": [],
  "xor_key": "CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
}
```

## Native leftover

8.6 MB after the linux .so. No ELF/PE/ZIP/CAFE at any XOR alignment.
AES-ECB/CBC/GCM with xor-key, sha256(key), .rodata keys: no verified magic.
`.so` strings: `JNI_OnLoad`, `DefineClass`, `DecryptionFailed`, AES-256-GCM/CTR (aws-lc).
This remaining payload is decrypted **inside** `JNI_OnLoad` after `RegisterNatives`.
100% of that layer = run the .so under Linux + JDK 21 (or Unicorn + JNI stubs).

carve scan: {'carves': [{'buf': 'leftover', 'tag': 'class', 'off': -1}, {'buf': 'leftover', 'tag': 'zip', 'off': -1}, {'buf': 'leftover', 'tag': 'elf', 'off': -1}, {'buf': 'leftover^key', 'tag': 'class', 'off': -1}, {'buf': 'leftover^key', 'tag': 'zip', 'off': -1}, {'buf': 'leftover^key', 'tag': 'elf', 'off': -1}, {'buf': 'raw_rest', 'tag': 'class', 'off': -1}, {'buf': 'raw_rest', 'tag': 'zip', 'off': -1}, {'buf': 'raw_rest', 'tag': 'elf', 'off': -1}]}

## 100% crack checklist

1. [x] unpack JAR
2. [x] detect ZKM21
3. [x] recover 7-xor key + linux .so
4. [~] emulate ZKM string methods (jvm_lite)
5. [ ] javavm/threadtear on JDK 17+ for indy bootstrap `h`
6. [ ] execute `JNI_OnLoad` (Linux) → AES leftover → win .dll + inner classes
