# Decryptor bases vs SFsociety

Mapped from `all docs.txt` clones in `D:\STREET-tool\github` onto this Sydney/ZKM21 loader.

| source | what we stole | what they cannot do on this JAR |
|---|---|---|
| Diobf `ZelixStringTransformer` / `ZKMCipher` | 7-xor tableswitch = `cipher2`; StaticInit split | their `(String)[C]` keyType1 method is inlined in ZKM21 clinit |
| java-deobfuscator `EnhancedStringEncryptionTransformer` | pattern `(II)Ljava/lang/String;` + VM init | needs javavm + JDK; our classes are major 65 |
| threadtear `StringObfuscationZKM` | isolate String.* and run proxy clinit | sandbox is Java, not Python; DES/indy incomplete |
| poke | bytecode normalize only | no ZKM, no native |
| c2j-native-deobfuscator | native unpack idea (emu + mock JNI) | target is j2cc/C++, ours is Rust `JNI_OnLoad` + aws-lc |
| Recaf / jar-analyzer | GUI inspect | not automated decrypt |

**Our stack on this sample**

1. Universal JAR unpack
2. ZKM21 marker + 7-xor key recovery → `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`
3. Blob `[u32be count=3][19B hdr][XOR ELF .so][AES leftover]`
4. `jvm_lite` — Python interpreter for clinit / a(III) (indy MH still incomplete)
5. Leftover 8.6 MB = AES inside native (`DecryptionFailed`, `DefineClass`, AES-256-GCM)

100% inner client = Linux + JDK 21 load the .so, or Unicorn with JNI stubs. Not possible on this box (JRE 1.8, Windows, ELF .so).
