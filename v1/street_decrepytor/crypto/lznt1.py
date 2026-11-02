# language: Python 3, file: lznt1.py
# LZNT1 (RtlDecompressBuffer format) — pure-python dekompressor
#
# Validiert 2026-09-05 gegen RtlCompressBuffer(0x0102)-Output auf
# der Werkbank (Cs2-External target-v2 Analyse: ecx=0x102 =
# LZNT1|ENGINE_MAXIMUM im Modul-Load-Call). Keine WinAPI-Abhaengigkeit.
from __future__ import annotations

import struct


def lznt1_decompress(src: bytes) -> bytes:
    """LZNT1-Dekompression (RtlDecompressBuffer-Format).

    Chunk-Aufbau: 2-Byte-Header (bits 0-11 = Laenge-1, bit 15 = komprimiert),
    danach Tokens: 1 Flag-Byte pro 8 Symbole; Symbol = Literal oder
    2-Byte-Referenz (offset-bits haengen von der Ausgabeposition ab).
    """
    out = bytearray()
    pos = 0
    n = len(src)
    while pos + 2 <= n:
        hdr = struct.unpack_from("<H", src, pos)[0]
        pos += 2
        chunk_len = (hdr & 0x0FFF) + 1
        compressed = bool(hdr & 0x8000)
        chunk_end = min(pos + chunk_len, n)
        if not compressed:
            out += src[pos:chunk_end]
            pos = chunk_end
            continue
        chunk_start_out = len(out)
        while pos < chunk_end:
            flags = src[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if flags & (1 << bit):
                    if pos + 2 > chunk_end:
                        pos = chunk_end
                        break
                    v = struct.unpack_from("<H", src, pos)[0]
                    pos += 2
                    out_pos = len(out) - chunk_start_out
                    if out_pos == 0:
                        continue
                    bits = max(4, (out_pos - 1).bit_length())
                    length_bits = 16 - bits
                    length = (v & ((1 << length_bits) - 1)) + 3
                    offset = (v >> length_bits) + 1
                    for _ in range(length):
                        out.append(out[-offset])
                else:
                    out.append(src[pos])
                    pos += 1
        pos = chunk_end
    return bytes(out)


def lznt1_status_names() -> dict[int, str]:
    """NTSTATUS-Codes von RtlDecompressBuffer."""
    return {
        0x00000000: "STATUS_SUCCESS",
        0xC0000242: "STATUS_BAD_COMPRESSION_BUFFER",
        0xC0000023: "STATUS_BUFFER_TOO_SMALL",
        0xC000000D: "STATUS_INVALID_PARAMETER",
    }
