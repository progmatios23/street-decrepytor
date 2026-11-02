# language: Python 3.11+, file: crypto/ciphers.py
# Extra ciphers for harvest decrypt: AES-128 ECB, ChaCha20, TEA/XTEA, XOR variants
from __future__ import annotations

import struct

# --- AES-128 ECB (decrypt). S-box / inv-S / Rcon are the FIPS tables. ---
_S = bytes([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
])
_SI = bytes([_S.index(i) for i in range(256)])
_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _expand(key: bytes) -> list[int]:
    w = list(key)
    i = 1
    while len(w) < 176:
        t = w[-4:]
        if len(w) % 16 == 0:
            t = [t[1], t[2], t[3], t[0]]
            t = [_S[x] for x in t]
            t[0] ^= _RCON[i]
            i += 1
        w.extend(a ^ b for a, b in zip(w[-16:-12], t))
    return w


def aes128_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(key) < 16 or len(data) < 16:
        return b""
    key = key[:16]
    rk = _expand(key)
    out = bytearray()
    for off in range(0, len(data) - (len(data) % 16), 16):
        state = list(data[off : off + 16])
        for i in range(16):
            state[i] ^= rk[160 + i]
        for rnd in range(9, 0, -1):
            # inv shift rows
            state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
            state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
            state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
            state = [_SI[b] for b in state]
            for i in range(16):
                state[i] ^= rk[rnd * 16 + i]
            ns = [0] * 16
            for c in range(4):
                i = c * 4
                a, b, d, e = state[i : i + 4]
                ns[i] = _mul(a, 14) ^ _mul(b, 11) ^ _mul(d, 13) ^ _mul(e, 9)
                ns[i + 1] = _mul(a, 9) ^ _mul(b, 14) ^ _mul(d, 11) ^ _mul(e, 13)
                ns[i + 2] = _mul(a, 13) ^ _mul(b, 9) ^ _mul(d, 14) ^ _mul(e, 11)
                ns[i + 3] = _mul(a, 11) ^ _mul(b, 13) ^ _mul(d, 9) ^ _mul(e, 14)
            state = ns
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
        state = [_SI[b] for b in state]
        for i in range(16):
            state[i] ^= rk[i]
        out.extend(state)
    return bytes(out)


def aes128_ecb_decrypt_key(data: bytes, key: bytes) -> bytes:
    return aes128_ecb_decrypt(key, data)


# --- ChaCha20 (RFC 7539), encrypt == decrypt ---
def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(s, a, b, c, d) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_xor(key: bytes, data: bytes, nonce: bytes | None = None, counter: int = 0) -> bytes:
    if len(key) < 16:
        return b""
    k = (key[:32] if len(key) >= 32 else (key[:16] * 2))[:32]
    n = (nonce or b"\x00" * 12)[:12]
    if len(n) < 12:
        n = n.ljust(12, b"\x00")
    const = b"expand 32-byte k"
    out = bytearray(len(data))
    off = 0
    ctr = counter
    while off < len(data):
        st = list(struct.unpack("<16I", const + k + struct.pack("<I", ctr) + n))
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12)
            _qr(w, 1, 5, 9, 13)
            _qr(w, 2, 6, 10, 14)
            _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15)
            _qr(w, 1, 6, 11, 12)
            _qr(w, 2, 7, 8, 13)
            _qr(w, 3, 4, 9, 14)
        ks = b"".join(struct.pack("<I", (w[i] + st[i]) & 0xFFFFFFFF) for i in range(16))
        chunk = data[off : off + 64]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
        off += 64
        ctr = (ctr + 1) & 0xFFFFFFFF
    return bytes(out)


def chacha20_xor_key(data: bytes, key: bytes) -> bytes:
    return chacha20_xor(key, data)


# --- TEA / XTEA decode (32 rounds) ---
def tea_decrypt(key: bytes, data: bytes) -> bytes:
    if len(key) < 16 or len(data) < 8:
        return b""
    k = struct.unpack(">4I", key[:16])
    out = bytearray()
    delta = 0x9E3779B9
    for off in range(0, len(data) - (len(data) % 8), 8):
        y, z = struct.unpack(">2I", data[off : off + 8])
        s = (delta * 32) & 0xFFFFFFFF
        for _ in range(32):
            z = (z - (((y << 4) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & 0xFFFFFFFF
            y = (y - (((z << 4) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & 0xFFFFFFFF
            s = (s - delta) & 0xFFFFFFFF
        out.extend(struct.pack(">2I", y, z))
    return bytes(out)


def tea_decrypt_key(data: bytes, key: bytes) -> bytes:
    return tea_decrypt(key, data)


def xtea_decrypt(key: bytes, data: bytes) -> bytes:
    if len(key) < 16 or len(data) < 8:
        return b""
    k = struct.unpack(">4I", key[:16])
    out = bytearray()
    delta = 0x9E3779B9
    for off in range(0, len(data) - (len(data) % 8), 8):
        y, z = struct.unpack(">2I", data[off : off + 8])
        s = (delta * 32) & 0xFFFFFFFF
        for _ in range(32):
            z = (z - ((((y << 4) ^ (y >> 5)) + y) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
            s = (s - delta) & 0xFFFFFFFF
            y = (y - ((((z << 4) ^ (z >> 5)) + z) ^ (s + k[s & 3]))) & 0xFFFFFFFF
        out.extend(struct.pack(">2I", y, z))
    return bytes(out)


def xtea_decrypt_key(data: bytes, key: bytes) -> bytes:
    return xtea_decrypt(key, data)


# --- XOR family ---
def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    kl = len(key)
    return bytes(data[i] ^ key[i % kl] for i in range(len(data)))


def xor_rol1(data: bytes, key: bytes) -> bytes:
    kl = max(1, len(key))
    return bytes((((data[i] ^ key[i % kl]) << 1) | ((data[i] ^ key[i % kl]) >> 7)) & 0xFF for i in range(len(data)))


def xor_add_index(data: bytes, key: bytes) -> bytes:
    kl = max(1, len(key))
    return bytes((data[i] ^ key[i % kl] ^ (i & 0xFF)) for i in range(len(data)))


def xor_feed(data: bytes, key: bytes) -> bytes:
    """CBC-style XOR: p[i] = c[i] ^ c[i-1] ^ key (c[-1]=0)."""
    kl = max(1, len(key))
    out = bytearray(len(data))
    prev = 0
    for i, b in enumerate(data):
        p = b ^ prev ^ key[i % kl]
        out[i] = p
        prev = b
    return bytes(out)
