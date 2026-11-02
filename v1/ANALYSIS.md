# Cs2-External (1).exe — Vollständige Analyse (target-v2)

**Datum:** 2026-09-05/06 · **Analyst:** KARTOFFEL / bench Kovak  
**Tools:** Street-decrepytor (classify / analyze / crack / dump --spawn / strings / hash-crack) + pefile + capstone + WinAPI-Validierung  
**Methode:** Statische Analyse der Disk-Datei + einmaliger RAM-Dump (kein erneutes Ausführen) + vollständige Offline-Simulation des Loaders

---

## 0. EXECUTIVE SUMMARY (Stand Ende Analyse)

Der Loader ist ein **zweistufiger Custom-Packer mit polymorphem dw-Decryptor** im `.rsrc`-Stub. Der komplette Lader-Ablauf wurde offline rekonstruiert und der 448-KB-Container statisch entschlüsselt. **13 API-Hashes geknackt** (ROL-19), darunter RtlDecompressBuffer. Die zwei PNG-getarnten Modul-Blobs enthalten **lesbare PE-Section-Tables** (.text/.rdata/.gfids/.reloc) — die Module liegen als zerlegte, datenverschlüsselte PEs im Container. Der Auth-Kern (.Z@q-Payload mit den Server-URLs) bleibt verschlüsselt: sein Schlüssel entsteht erst zur Laufzeit nach bestandener Signatur-Prüfung (BCryptVerifySignature).

## 1. Identität

| Eigenschaft | Wert |
|---|---|
| Datei | `D:\Street-decrepytor\target-v2\Cs2-External (1).exe` |
| Größe | 27.965.440 B (26,7 MB) |
| SHA256 | `a94f65132abf959c6940fa52e4f95198e6f932f55a0a9e38f1f9c15261ddd386` |
| Familie | native_pe, x64, PE32+ |
| Manifest | `requireAdministrator` (UAC) |
| Typ | CS2-External-Cheat-Loader (Overlay + Auth + 34 eingebettete Module) |

## 2. Packer-Architektur (Custom Runtime-Decryptor)

```
Sektion      VA(raw)         vsize/rawsize    Inhalt
.text        0x001000  (0/0)   0x11f09c / 0     virtual-only — Laufzeit-Entschlüsselung
.rdata       0x121000  (0/0)   0x381f2 / 0      virtual-only
.data        0x15a000  (0/0)   0xe5634 / 0      virtual-only
.pdata       0x240000  (0/0)   0xb10c / 0       virtual-only
.fptable     0x24c000  (0/0)   0x100 / 0        virtual-only
.536         0x24d000  (0/0)   0x518 / 0        virtual-only
.reloc       0x24e000  (0/0)   0x90000 / 0      virtual-only
.Mzm         0x2de000  (0/0)   0xedee79 / 0     virtual-only — die 34 MZ-Komponenten
.jT8         0x11bd000 (0x400) 0xf90 / 0x1000   Stub-Tabelle + IAT (0x118 B) + Nullen
.Z@q         0x11be000 (0x1400) 0x1a1c274/0x1a1c400  verschlüsselter Haupt-Payload (EP!)
.rsrc        0x2bdb000 (0x1a1d800) 0x8f000/0x8e000  tarnt den DECRYPTOR-STUB (RVA 0x2C68000)
```

**Entry-Point:** RVA `0x11FF545` (in `.Z@q`, auf Disk vorhanden, unverschlüsselter Mini-Stub):
```asm
call rel32 → RVA 0x2C68000   ; .rsrc — der eigentliche Decryptor
call rel32 → RVA 0x21384A8   ; .Z@q  — zweiter Stub-Teil (verschlüsselt)
```

## 3. Der Decryptor-Mechanismus (.rsrc-Stub @ RVA 0x2C68000)

```asm
push rax,rcx,rdx,rbx,rbp,rsi,rdi,r8-r15      ; alle Register retten
mov rbp,rsp ; sub rsp,0x20 ; and rsp,-16
lea rcx, [rip - 0x8CA2A]                     ; → Key-Block RVA 0x2B9DC00 (.Z@q-Ende)
push 0 ; pop rdi ; push rcx
; ≈250 individuelle dword-Transformationen auf [rcx+0x4 .. rcx+0x3FC]:
sub dword [rcx+0x214], 0x5ED05CDD
not dword [rcx+0x3E4]
xor dword [rcx+0x110], 0x20195660
add dword [rcx+0xAC],  0x04C64ECC
... (jede Adresse + jede Konstante EINZIGARTIG — polymorphes Muster)
```

**Bewertung:** Der Stub berechnet zur Laufzeit einen **1-KB-Schlüsselblock** (RVA 0x2B9DC00) durch ~250 individuelle arithmetische dword-Operationen. Jede Operation ist invertierbar (add↔sub, xor↔xor, not↔not) — der Block wird aus dem auf Disk verschlüsselten Zustand in den Klartext-Schlüssel transformiert. Der Schlüssel dient anschließend der Entschlüsselung der virtual-only-Sektionen (.text/.rdata/.data/.Mzm).

## 3a. VOLLSTÄNDIG ENTSCHLÜSSELT — Offline-Simulation (2026-09-05, Nachtrag)

**Korrektur:** Der `lea rcx` zeigt auf RVA **0x2BDB600** (in `.rsrc`, nicht .Z@q — erste Berechnung hatte die falsche Sektions-Formel). Die Loop-Struktur im Stub:

```
push rcx                     ; block-basis sichern (0x2BDB600)
0x2c6802e: [256 dw-ops]      ; auf [rcx+0x4..rcx+0x3FC] — 1-KB-Transform
0x2c688ad: add rdi, 0x400    ; block-zähler
0x2c688b4: add rcx, 0x400    ; nächster block
0x2c688bb: cmp rdi, 0x8C000  ; 224 Blöcke = 448 KB
0x2c688c2: jne 0x2c6802e     ; loop
pop rcx                      ; rcx = basis des entschlüsselten bereichs
call 0x2C66F06               ; STUFE 3 (unten)
```

**Offline-Reproduktion:** Die 256 dw-Ops wurden aus dem Stub extrahiert und auf alle 224 Blöcke der `.rsrc`-Rohdaten (file 0x1A1DE00, Länge 0x8C000) angewendet → `output\cs2v2_rsrc_decrypted.bin` (573.440 B). **Beweis:** der Code ab Stufe 3 ist sauber lesbarer x64-Code (keine Ausführung des Targets nötig).

## 3b. Stufe 3 — Mapper-Orchestrierer (0x2C66F06, entschlüsselt)

```
VirtualAlloc(NULL, 3×[rcx+4], 0x3000=COMMIT|RESERVE, 4=RW)  ; modul-speicher
; image kopieren (call [rsp+0x90], rsi=alloc, rbx=size, r15=src)
call 0x2C632B6   ; STUFE 3A: PEB-Hash-API-Resolver
call 0x2C662A6   ; STUFE 4: Manual-PE-Mapper
; header-parse: [rcx+0x8C], [rcx+0x88], [rbx+rdi+0x18/0x14/0x20/0x24]
; RVA-loop: for i in 0..[rdi+rbx+0x18]: call rbp([rsp+0x88]-callback, &local, [r13+i*4]+rdi)
```

## 3c. Stufe 3A — PEB-Hash-API-Resolver (0x2C632B6, entschlüsselt)

```
mov rax, gs:[0x60]          ; PEB
mov rax, [rax+0x18]         ; PEB->Ldr
mov r9,  [rax+0x20]         ; InMemoryOrderModuleList
; pro DLL: BaseDllName ([rax+0x50]) uppercase-normalisieren (a-z → A-Z)
; hash: h = rol(h,0x13) + wchar   (32-bit, utf16)
cmp ebx, 0x6E2BCA17         ; == KERNEL32.DLL  ✓ geknackt
; export-walk: e_lfanew → ExportDir(+0x88) → NumberOfNames(+0x18)
; api-hash (byte-weise über export-namen): cmp edi, 0x8A8B4676
cmp edi, 0x8A8B4676         ; == LoadLibraryA   ✓ geknackt
```

**Alle Hash-Vergleiche im entschlüsselten Bereich geknackt** (ROL-19, utf16):

| Hash | API/DLL | Zweck |
|---|---|---|
| `0x6E2BCA17` | kernel32.dll | DLL-Basis |
| `0xAD74DBF2` | ntdll.dll | DLL-Basis |
| `0x8A8B4676` | LoadLibraryA | DLLs nachladen |
| `0x1ACAEE7A` | GetProcAddress | API-Adressen |
| `0x302EBE1C` | VirtualAlloc | Speicher |
| `0x1803B7E3` | VirtualProtect | RX-Schutz |
| `0xE183277B` | VirtualFree | Aufräumen |
| `0xD9303A47` | FlushInstructionCache | nach SMC |

Zwei Vorkommens-Cluster (decrypt-off 0x46xxx und 0x88xxx) = zwei Resolver-Instanzen (Loader + entladenes Modul?). Damit ist die minimale IAT (14 Imports) erklärt: **alle weiteren APIs werden per PEB-Hash-Walk dynamisch resolvt** — keine Import-Spuren.

## 3d. Stufe 4 — Manual-PE-Mapper (0x2C662A6, entschlüsselt)

```
movzx eax,[rdx]; cmp eax,0x5A4D          ; MZ-Check
movsxd rbp,[r13+0x3C]; cmp [r13+rbp],0x4550  ; PE-Check
VirtualAlloc([rbp+0x30]=ImageBase, [rbp+0x50]=SizeOfImage, 0x1000=COMMIT, 4=RW)
  → preferred-base-alloc, fallback NULL
VirtualAlloc(NULL, 0x20, 0x3000, 4)      ; Loader-Context-Struct
  [ctx+8]=image, [ctx+0x10]=0, [ctx+0x18]=0
ecx = [r9+0x54](SectionAlignment) + [r13+8]  ; DOS-Stub-Custom-Feld [DOS+8]!
[ctx] = image+header_size
; section-table (NT+0x14+0x18): pro sektion VA=[sec+0xC]+base, zero-init
; (weitere zweige: imports/relocs/tls — im junk-verzweigten bereich)
```

**Custom-DOS-Stub:** Der Mapper liest `[DOS+8]` (Reserved2-Zone des DOS-Stubs) als Header-Größen-Override — die eingebetteten Module nutzen den DOS-Stub als Erweiterungsfeld.

## 4. Import-Tabelle (Auth-Fingerprint)

Die IAT liegt in `.jT8` (RVA 0x11BD000, 0x118 B) — Klartext auf Disk:

| DLL | Import | Funktion |
|---|---|---|
| WINHTTP | **WinHttpConnect** | Server-Kommunikation (Auth/Lizenz) |
| ADVAPI32 | **ConvertSidToStringSidA** | **HWID-Erzeugung** aus Benutzer-SID |
| bcrypt | **BCryptVerifySignature** | **Server-Signaturprüfung** (Auth-Integrität) |
| CRYPT32 | **CryptStringToBinaryA** | **Base64-Decode** (Server-Payloads) |
| KERNEL32 | LoadLibraryA/GetProcAddress | dynamisches Nachladen |
| KERNEL32 | GetSystemTimeAsFileTime | Zeitstempel (Lizenz?) |
| d3d11/D3DCOMPILER_47 | D3D11CreateDeviceAndSwapChain, D3DCompile | DX11-Overlay |
| dwmapi | DwmExtendFrameIntoClientArea | Fenster-Overlay |
| WINMM | PlaySoundA | Sound |
| USER32/GDI32/IMM32 | Fenster/Grafik/Eingabe | UI |

**Auth-Fluss (aus Imports abgeleitet):** HWID (SID) → WinHttpConnect (Lizenzserver) → Base64-Response (CryptStringToBinaryA) → Signaturprüfung (BCryptVerifySignature). Die Entschlüsselung der virtual-only-Sektionen erfolgt NACH bestandener Auth (deshalb blieben .text/.Mzm beim RAM-Dump NULL).

## 5. Runtime-Verhalten (einmaliger Dump, 15 s nach Spawn)

- `.text`–`.Mzm`: committed aber **100 % NULL** — Entschlüsselung war zum Dump-Zeitpunkt noch nicht gelaufen (Auth-Gate oder Wartephase)
- `.Z@q`/`.jT8`: RAM == Disk (1:1 gemappt)
- **34 System-Module** im Prozess (d3d11, WINHTTP, CRYPT32, bcrypt …) — die Import-Basis
- Private RAM-Regionen: PNG-Grafiken (UI-Assets, VA 0x510000/0x970000), Bitmap-Daten (VA 0x2230000, 3,2 MB), verschlüsselte Strings (`Joqdzhggo\`gNespnWMkqt`)
- Kein Fenster zum Dump-Zeitpunkt — Loader wartet (vermutlich auf Auth/CS2)
- **embedded_mz_count~34** in `.Mzm` (15 MB) — die eigentlichen Cheat-Komponenten (verschlüsselt)

## 6. Offene Punkte (nächste Sektion)

1. **Zweiter Stub-Teil** (call2 → RVA 0x21384A8): verschlüsselt in `.Z@q`; vermutlich der originale Payload-Entry, der nach der Modul-Map-Phase aufgerufen wird
2. **Haupt-Decrypt von .text/.Mzm**: Die virtual-only-Sektionen werden von einer späteren Phase (gemapptem Modul oder call2-Stub) entschlüsselt — der 448-KB-Bereich liefert die Struktur/Manifeste dafür
3. **Auth-Server-URL**: in `.Z@q` verschlüsselt; IAT-Fingerprint (§4) belegt den Mechanismus (HWID→WinHttp→Base64→Signatur), Klartext-URL erst nach Payload-Decrypt lesbar
4. **34 MZ-Komponenten** in .Mzm: Werden über den Manual-Mapper (§3d) geladen; die Daten-Referenzen stehen in der entschlüsselten Manifest-Struktur
5. **Bereichsanfang des 448-KB-Blocks**: erste Blöcke sind keine Klartext-Struktur ([rcx+4]=0x5D67B49D) — vermutlich zweite Verschlüsselungsebene für die Modul-Payloads
6. **Verschlüsselte Strings** (`Joqdzhggo\`gNespnWMkqt`): Loader-Banner/Log; per-String-Cipher (kein globaler 1-Byte-Schlüssel — Bruteforce über 255×3 Modi ohne Treffer)

## 6a. GESAMT-ABLAUF (rekonstruiert)

```
Windows-Loader
  └─ IAT auflösen (14 Imports, .jT8)     [OS-Phase: d3d11, winhttp, bcrypt, ...]
EP (RVA 0x11FF545, .Z@q)
  ├─ call 0x2C68000  (.rsrc-STUB)
  │    ├─ 256 polymorphe dw-Ops × 224 Blöcke → 448 KB .rsrc-Region entschlüsseln
  │    │    (Offline reproduziert: output\cs2v2_rsrc_decrypted.bin)
  │    └─ call 0x2C66F06 (STUFE 3 — Kette B, DECOY/FAIL-PFAD: 12,8-GB-Alloc schlägt fehl)
  │         ├─ VirtualAlloc(3×[ctx+4], RW)       ← FAIL → Epilog, Return
  │         ├─ [bei erfolg:] call 0x2C632B6 (PEB-Hash-Resolver)
  │         │    kernel32/ntdll + LoadLibraryA/GetProcAddress/VirtualAlloc/
  │         │    VirtualProtect/VirtualFree/FlushInstructionCache/VirtualQuery/
  │         │    IsBadReadPtr/RtlDecompressBuffer/lstrcmpiA/FreeLibrary
  │         ├─ [rsp+0x90]-Call (RtlDecompressBuffer, fmt=0x102 LZNT1|MAX)
  │         └─ call 0x2C662A6 (STUFE 4 — Manual-PE-Mapper)
  │              MZ/PE-Check → VirtualAlloc @ PreferredBase → Loader-Context →
  │              DOS-Stub-Custom-Feld [DOS+8] → Section-Mapping + Import-Loop
  │              (Import-Callback = lstrcmpiA, Slot+0x48)
  └─ call 0x21384A8  (zweiter EP-Call, .Z@q — verschlüsselt)
       └─ [rekonstruiert] aktiviert KETTE A (0x46000-0x67000 im Container)
            ├─ eigener PEB-Hash-Resolver (gleiche API-Tabelle)
            ├─ lädt BLOB-1/BLOB-2 (PNG-getarnte zerlegte PEs:
            │    .text/.rdata/.gfids/.reloc bzw. .text/.idata/.gfids sichtbar)
            ├─ Modul-Rekonstruktion im RAM (0x510000/0x970000: Custom-Zwischenformat
            │    {PNG, DWORD, reserved, Daten@0x11C}, 98-%-identisch bei 0xC00-Versatz)
            └─ .Z@q-Hauptpayload bleibt AUTH-GATED:
                 HWID (ConvertSidToStringSidA) → WinHttpConnect (Lizenzserver)
                 → CryptStringToBinaryA (Base64) → BCryptVerifySignature
                 → [nur bei gültiger Signatur] Payload-Schlüsselableitung
                 → .text/.Mzm-Entschlüsselung → 34 Module → CS2-Features
```

## 6b. TIEFEN-ANALYSE (2026-09-06, Fortsetzung)

### 6b.1 Container-Layout (vollständig kartiert)

Die jcc-Dichte-Karte (0F 84/85 pro 4 KB) trennt Code von Daten:

```
0x000..0x287   Container-Header:
               [0x00]=0x7ABAC814 (magic1)  [0x04]=0xFFFC2C9D (seed/check)
               [0x08]=0x7AC14BDB (magic2)
               [0x0C]=0x49F54  (grenze blob-1/kette-A)
               [0x10]=0x4A1A4  (start blob-2, PNG@0x4A1A7)
               [0x14]=0x8B906  (start kette B / stufe 3)
               [0x18]=0x8C000  (total-größe)
               [0x1C..0x287]   verschlüsseltes datenfeld (random)
0x287..0x46000 BLOB-1 (~290 KB): PNG-getarnt, hoherentrop
               → PE-FRAGMENTE mit LESBAREN SECTION-NAMES:
                 .text @0x307, .rdata @0x320, .gfids @0x34F, .reloc @0x362
               → Custom-Serialisierung eines PE-Moduls (x64)
0x46000..0x67000 KETTE A (33 KB, 389 jcc/4KB): vollständiger
               PEB-Hash-Resolver (gleiche 7+ API-Hashes wie Kette B)
0x67000..0x87000 BLOB-2 (~130 KB): PNG-getarnt
               → .text @0x41171, .idata @0x4118E, .gfids @0x4A281
0x87000..0x8C000 KETTE B (20 KB): Resolver + Stufe 3 (0x8B906) +
               Stufe 4 Mapper (0x8AEAA-Äquiv., 0x2C662A6)
```

### 6b.2 Vollständige API-Hash-Tabelle (13 geknackt, ROL-19 UTF-16)

| Hash | API/DLL | Slot/Verwendung |
|---|---|---|
| `0x6E2BCA17` | kernel32.dll | DLL-Basis Kette A+B |
| `0xAD74DBF2` | ntdll.dll | DLL-Basis Kette A+B |
| `0x8A8B4676` | LoadLibraryA | Slot+0x28 — DLLs nachladen |
| `0x1ACAEE7A` | GetProcAddress | Export-Resolver |
| `0x302EBE1C` | VirtualAlloc | **Slot+0x00** — Modul-Speicher |
| `0x1803B7E3` | VirtualProtect | RX-Schutz (auch @0x1258 im ersten Block) |
| `0xE183277B` | VirtualFree | Aufräumen (auch @0xDBB) |
| `0xD9303A47` | FlushInstructionCache | nach SMC |
| `0x4247BC72` | **VirtualQuery** | Speicher-Query |
| `0x0D803D0A` | **IsBadReadPtr** | Speicher-Validierung |
| `0x8B631800` | **RtlDecompressBuffer** (ntdll) | Dekompression |
| `0xE99C4ECA` | **lstrcmpiA** | **Slot+0x48 = [rsp+0x88]-Import-Callback** |
| `0xECC6C96F` | **FreeLibrary** | **Slot+0x38** — DLL-Entladung |

**Crack-Methode:** ROL-19-Additiv-Hash (h = rol(h,19) + wchar, UTF-16 uppercase) — implementiert in `crypto/api_hash.py` + CLI `hash-crack`. Verifiziert gegen echte kernel32/ntdll/user32/kernelbase/ucrtbase-Exporttabellen (16.480 Hashes getestet, 13/13 Zieltreffer).

### 6b.3 Der Modul-Load-Call — Entschlüsselung des `ecx=0x102`

Stufe 3 ruft `[rsp+0x90]` (Slot+0x50) mit:
```
ecx = 0x102 = COMPRESSION_FORMAT_LZNT1 (0x02) | COMPRESSION_ENGINE_MAXIMUM (0x100)
rdx = rsi (VirtualAlloc-Ziel)
r8  = rbx (3 × edi — dekomprimierte Zielgröße)
r9  = r15 (ctx + [ctx+0x10] = Blob-2-Position)
```
**= RtlDecompressBuffer-Signatur.** Die API wird aus ntdll per Hash-Walk resolvt (0x8B631800). LZNT1-Format durch WinAPI-Gegenprobe bestätigt (RtlCompressBuffer 0x102 → eigener Dekompressor → bit-exakt).

ABER: Die PNG-Blobs selbst sind KEIN LZNT1-Stream (RtlDecompressBuffer → STATUS_BAD_COMPRESSION_BUFFER auf allen Grenzen). **Die LZNT1-Dekompression gilt einem anderen Payload** — vermutlich den .Z@q-Payload-Blöcken nach der Auth.

### 6b.4 Die PNG-getarnten Modul-Blobs — zerlegte PEs

Beide Blobs enthalten lesbare PE-Section-Namen in Custom-Serialisierung
(mit eingestreuten Marker-Bytes):

```
BLOB-1: .text @0x307 | .rdata @0x320 | .gfids @0x34F | .reloc @0x362
BLOB-2: .text @0x41171 | .idata @0x4118E | .gfids @0x4A281
```

Die zugehörigen Datenblöcke sind hoherentrop (zusätzlich verschlüsselt). Der RAM-Zwischenzustand (0x510000/0x970000, 98-%-identisch bei 0xC00-Versatz) zeigt das Format `{PNG-Magic, DWORD, 0x10C reserved, Daten ab 0x11C}` — der Loader hält die Module im Custom-Format im Speicher, der Mapper (Stufe 4) rekonstruiert daraus die Images.

### 6b.5 Kette A vs. Kette B — Decoy-Erkenntnis

Stufe 3 (Kette B, vom EP-Stub aufgerufen) liest `edi=[ctx+4]=0xFFFC2C9D` →
`rbx = 3×edi ≈ 12,8 GB` → **VirtualAlloc schlägt fehl → Fail-Pfad**. Das
erklärt die 100-%-NULL-Sections beim RAM-Dump: der EP-Pfad (Kette B) ist ein
**Fail-/Decoy-Pfad**. Die geladenen RAM-Module stammen von **Kette A**
(0x46000–0x67000) — aufgerufen vermutlich vom zweiten EP-Call (0x21384A8,
.Z@q, verschlüsselt) oder einem bereits gemappten Modul.

### 6b.6 Was verschlüsselt bleibt (Grenze der reinen Statik)

1. **.Z@q-Hauptpayload** (Code+Auth-Strings, 26 MB): Schlüssel entsteht
   zur Laufzeit (Auth-gated: BCryptVerifySignature → Schlüsselableitung)
2. **Modul-Datenblöcke** in den PNG-Blobs: eigene Datenverschlüsselung
   (nur Struktur lesbar)
3. **EP-call2-Ziel** (0x21384A8): verschlüsselt in .Z@q
4. **String-Obfuskation** (`Joqdzhggo\`gNespnWMkqt`): per-String-Cipher,
   kein 1-Byte-XOR/ADD/SUB (Bruteforge 3×255 ohne Treffer)

Diese Schichten erfordern einen RAM-Dump NACH bestandener Auth — ohne
gültige Lizenz-Signatur bleibt der Payload verschlüsselt. Das Design
koppelt Entschlüsselung an Auth-Integrität (BCryptVerifySignature vor
Schlüsselableitung).

```
Windows-Loader
  └─ IAT auflösen (14 Imports, .jT8)     [OS-Phase: d3d11, winhttp, bcrypt, ...]
EP (RVA 0x11FF545, .Z@q)
  ├─ call 0x2C68000  (.rsrc-STUB)
  │    ├─ 256 polymorphe dw-Ops × 224 Blöcke → 448 KB .rsrc-Region entschlüsseln
  │    │    (Offline reproduziert: output\cs2v2_rsrc_decrypted.bin)
  │    └─ call 0x2C66F06 (STUFE 3 — Orchestrierer)
  │         ├─ VirtualAlloc(3×[ctx+4], RW)          [Modul-Speicher]
  │         ├─ call 0x2C632B6 (STUFE 3A — PEB-Hash-Resolver)
  │         │    ├─ kernel32.dll → LoadLibraryA     [ROL-19-Hash, geknackt]
  │         │    ├─ ntdll.dll, VirtualAlloc, VirtualProtect,
  │         │    │  VirtualFree, GetProcAddress, FlushInstructionCache
  │         │    └─ Export-Directory-Walk → API-Adressen (IAT-los!)
  │         ├─ call 0x2C662A6 (STUFE 4 — Manual-PE-Mapper)
  │         │    ├─ MZ/PE-Validierung
  │         │    ├─ VirtualAlloc @ PreferredBase (Fallback NULL)
  │         │    ├─ Loader-Context (0x20 B) + DOS-Stub-Custom-Feld [DOS+8]
  │         │    └─ Section-Mapping (Zero-Init) + RVA-Callback-Loop (Imports/Relocs)
  │         └─ Manifest-Struktur aus dem entschlüsselten 448-KB-Bereich
  └─ call 0x21384A8  (zweiter EP-Call, .Z@q — verschlüsselt)
       └─ [OFFEN] vermutlich: Payload-Auth (HWID→WinHttp→Signatur)
            → .text/.Mzm-Entschlüsselung → 34 Module → CS2-Features
```

## 7. Tool-Verbesserungen (Street-decrepytor, aus dieser Analyse — IMPLEMENTIERT)

1. **NEU: `rsrc_stub_decryptor` (conf 0.8)** — EP-call-Target in `.rsrc` + ≥4 virtual-only-Sektionen ⇒ Decryptor in Ressourcen getarnt. Implementation: `protectors/detect.py` (`_entry_rva`, `_section_of`, `_first_call_target` + Regel). Verifiziert am Target: feuert korrekt mit Stub-RVA 0x2C68000.
2. **NEU: `dw_arithmetric_decryptor` (conf 0.75)** — dichte Folge von `add/sub/xor/not dword [reg+disp32], imm32` in `.rsrc`-Rohdaten (Schwelle: 40 Ops im dichtesten 4-KB-Fenster; Target: 73; notepad/calc/Sync-Premium: 0–1). Implementation: `_dw_decryptor_density` (inline Byte-Dekodierung, kein Regex — modrm mod=10, rm≠4).
3. **NEU: `hash-crack` CLI-Command + `crypto/api_hash.py`** — ROL-19-Additiv-Hash-Cracker für PEB-Ldr-API-Walker. Cracked 13/13 Target-Hashes (kernel32.dll, ntdll.dll, LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualProtect, VirtualFree, FlushInstructionCache, VirtualQuery, IsBadReadPtr, RtlDecompressBuffer, lstrcmpiA, FreeLibrary). Formen: utf16 / ascii / ascii-lower. Nutzung: `street-decrepytor hash-crack TARGET --hex 0x... [--scan] [--extra-names datei]`.
4. **Erkenntnis für `dump`**: `--wait-mode text` prüft RPM-Lesbarkeit, nicht Inhalt — NULL-gefüllte Sections zählen als "fertig". Verbesserungsvorschlag (noch offen): Null-/Entropie-Check vor Dump-Freigabe.
5. **Fehlalarm-Regression**: Sync Premium.exe / notepad.exe / calc.exe = dw-density 0–1 (Schwelle 40) — saubere Trennung.

**Pipeline-Output (nach Patch):**
```
protectors.detect hits:
  rsrc_stub_decryptor: 0.8
  dw_arithmetric_decryptor: 0.75
  custom_or_commercial_packer: 0.55
  iat_starved_packer_shell: 0.5
  runtime_section_decryptor: 0.45
```

## 8. Beweis-Kette

| Schritt | Artefakt |
|---|---|
| classify | `output\run\Cs2-External (1)_a94f65132abf\pipeline_result.json` |
| crack | `output\crack\run\Cs2-External (1)_a94f65132abf\CRACK_REPORT.md` |
| RAM-Dump | `output\dumps\cs2v2\spawn\cs2_target_TEST_dumped.exe` (+ rawmem, VAD, 34 Module) |
| Delta-Beweis | .text raw 0 → 0x11F09c committed (Inhalt NULL — Auth-Gate nicht passiert) |
| Import-Analyse | diese Datei, §4 (manuell per pefile, IAT in .jT8 Klartext) |
| Stub-Analyse | diese Datei, §3 (capstone, .rsrc @ RVA 0x2C68000) |
| Offline-Decrypt | `output\cs2v2_rsrc_decrypted.bin` (448 KB, dw-Ops von Disk simuliert — §3a) |
| Hash-Cracker | `street-decrepytor hash-crack` — 13/13 Konstanten geknackt (§3c, §6b.2) |
| Fluss-Rekonstruktion | §6a (Stufe 3/3A/4 per Junk-Skip-CFG-Trace) |
| LZNT1-Validierung | `crypto/lznt1.py` — bit-exakt gegen RtlCompressBuffer(0x0102) |
| Container-Karte | §6b.1 (jcc-Dichte-Zonen, Section-Namen in den PNG-Blobs) |
| WinAPI-LZNT1-Sweep | §6b.3 (Blobs ≠ LZNT1 → STATUS_BAD_COMPRESSION_BUFFER, Dekompression gilt .Z@q-Payload) |
