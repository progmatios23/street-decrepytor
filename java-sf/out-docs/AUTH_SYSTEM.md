# Sydney auth system — from decrypted layers + live probes

## Stack we already broke

1. JAR unpack, ZKM21 marker
2. 7-xor key `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`
3. Native table: linux .so / windows `sydney_loader.dll` / macos dylib
4. Zelix StringEncryptionTransformer: **109 strings**, CFR of `Natives.load`
5. JNI host: `System.load(sydney_1_pe.dll)` → this MessageBox

## Boot order (emulated)

```
Fabric preLaunch  FabricEntryPoint.onPreLaunch() = empty
Mixin plugin clinit  → h.a("e")  ≈ Natives.load()
Natives.load()
  getResource(blob sydney$e5f314…)
  ByteBuffer BE, count=3
  pick arch+ext (.dll / amd64)
  XOR payload with key
  Files.createTempFile + System.load
JNI_OnLoad  (sydney_loader.dll)
  getenv USERPROFILE
  CreateFileW  %USERPROFILE%\.sydney\authorization.bin
  if missing/empty/invalid:
      MessageBoxW "Sydney" /
        "A valid authentication key could not be found. Please try logging in."
      natives NOT registered
  if local parse ok:
      stall (no DNS in 10s) — likely bcrypt/signature or later TLS
after auth:
  RegisterNatives:
    Natives.getResource / getResources / getUserId / getUsername
    mixin plugin + FabricEntryPoint.onInitialize
    MixinServiceKnot.getClassBytes → native class bytes
    NativeResourcePack → assets via getResource
```

`getUserId()` / `getUsername()` are **native after** this gate (HWID + account).

## Probe results (`out/auth_probe.json`)

Frida: MessageBoxW auto-IDOK, log CreateFileW of authorization.bin.

| dummy `authorization.bin` | MessageBox |
|---|---|
| missing | YES — invalid key |
| empty (0 bytes) | YES |
| ascii `sydney-test-token` (17) | no box in 10s (passed local, then stall) |
| JSON `{"token":"deadbeef",...}` | no box, stall |
| 32× `\\x00` | no box, stall |
| 64× `\\xFF` | YES — invalid key |

Local check ≈ **file exists, size > 0, parses as a blob** (not all-0xFF).
Online/signature step does **not** call `getaddrinfo` in the first 10s.
No hostname in the DLL as plaintext (constructed / encrypted).

## Files / monitor

| path | role |
|---|---|
| `%USERPROFILE%\\.sydney\\authorization.bin` | session token from official login |
| `jnihost/hook_auth.js` | Frida: MessageBox, CreateFile, DNS |
| `jnihost/probe_auth.py` | dummy-key matrix |
| `auth_monitor.py` | `status` / `watch` on that file |
| `jnihost/monitor.bat` | start watcher |

```
python D:\STREET-tool\SFsociety-decryptor\auth_monitor.py status
python D:\STREET-tool\SFsociety-decryptor\auth_monitor.py watch
python D:\STREET-tool\SFsociety-decryptor\jnihost\probe_auth.py
```

A real key is written only by the Sydney launcher after login on sydneyclient.net.
Copy it to `.sydney\\authorization.bin` then re-run DumpHost to dump `getResource`.

## Crack attempts (this session)

| attempt | result |
|---|---|
| NOP `je` at JNI_OnLoad+0x140b (auth None) | process dies |
| fake Option ptr + skip `0x59c20` | dies after string decrypt |
| pad decrypt buffers | process lives, **no** inner classes on heap |
| dummy `sydney-test-token` (no MessageBox) | process dies ~7s on success-path |
| memory scan rw- for CAFEBABE | only JVM `LambdaForm$MH` |
| BCryptDecrypt import | none (AES is static aws-lc) |

Inner class AES runs **only** after a key that survives native verify (not dummy ascii/json/zeros).
Those dummies skip the MessageBox then abort. Heap never contains `net.sydneyclient` game classes.

**Working unpack path:** drop a real `authorization.bin` → `jnihost\run_after_login.bat` → `DumpHost` `getResource` → `out\inner\`.

