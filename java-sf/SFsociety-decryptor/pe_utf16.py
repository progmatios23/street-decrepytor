from pathlib import Path

data = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll").read_bytes()

needles = [
    "Natives",
    "sydney",
    "sydneyclient",
    "getResource",
    "getResources",
    "getUserId",
    "getUsername",
    "FabricEntryPoint",
    "onInitialize",
    "JNI_OnLoad",
    "RegisterNatives",
    "FindClass",
    "DefineClass",
    "net/sydney",
    "loader",
]


def find_utf16(s: str):
    raw = s.encode("utf-16le")
    hits = []
    start = 0
    while True:
        i = data.find(raw, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 2
        if len(hits) > 8:
            break
    return hits


print("utf8 / utf16le")
for s in needles:
    u8 = data.find(s.encode())
    u16 = find_utf16(s)
    if u8 >= 0 or u16:
        print(f"  {s!r:20} utf8={u8} utf16={u16[:4]}")

# dump utf16 strings that look like java names
print("\nutf16-le java-ish:")
i = 0
n = 0
while i < len(data) - 8 and n < 40:
    if data[i + 1] == 0 and 32 <= data[i] < 127:
        chars = []
        j = i
        while j + 1 < len(data) and data[j + 1] == 0 and 32 <= data[j] < 127:
            chars.append(chr(data[j]))
            j += 2
        if len(chars) >= 8:
            s = "".join(chars)
            if "/" in s or "sydney" in s.lower() or s.startswith("Java") or "Class" in s or "native" in s.lower():
                print(f"  @{i:#x} {s[:120]}")
                n += 1
        i = j
    else:
        i += 1
print("done")
