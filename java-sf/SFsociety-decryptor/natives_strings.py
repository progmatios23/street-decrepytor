from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sfsociety import class_methods, extract_7xor_keys, mutf8_to_chars
from emulate_zkm import ldc_strings_and_offsets, zkm_7xor_chars

p = Path(r"D:\STREET-tool\out\unpacked\net\sydneyclient\loader\Natives.class")
data = p.read_bytes()
this, cp, methods = class_methods(data)
clinit = next(m for m in methods if m[0] == "<clinit>")
keys = extract_7xor_keys(clinit[3])
strings, offsets = ldc_strings_and_offsets(clinit[3], cp)
print("keys", keys, "offsets", offsets)
for i, s in enumerate(strings):
    d = zkm_7xor_chars(s, keys)
    vis = "".join(ch if 32 <= ord(ch) < 127 else f"\\x{ord(ch):02x}" for ch in d)
    print(f"--- ldc {i} len={len(s)} xor ---")
    print(vis)
    print("repr", d[:80])
