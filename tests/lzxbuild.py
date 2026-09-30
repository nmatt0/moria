#!/usr/bin/env python3
"""Minimal LZX stream writer, shared by the CE ROM and CAB regression tests.

Writing a real LZX *compressor* is not needed to test the framings around it:
the format defines an uncompressed block type that stores bytes verbatim, so a
few dozen lines produce streams a conformant decoder must accept. The Huffman /
match decoding itself is exercised by the sample-derived fixtures in
test_wince_rom.py.

Bits go out most-significant-first inside 16-bit little-endian words, which is
what the LZX bitstream layer consumes.
"""
import struct


class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.cur = 0
        self.n = 0

    def put(self, value, bits):
        for i in range(bits - 1, -1, -1):
            self.cur = (self.cur << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 16:
                self.out += struct.pack("<H", self.cur)
                self.cur = 0
                self.n = 0

    def align_word(self):
        """Pad with zero bits to the next 16-bit word boundary."""
        while self.n:
            self.put(0, 1)


def lzx_stored_stream(data, intel_filesize=0):
    """An LZX stream that decodes to exactly `data` via one uncompressed block.

    Layout: a 1-bit "no x86 preprocessing" header, a 3-bit block type (3 =
    uncompressed), a 24-bit block length, padding to a word boundary, the
    stored R0/R1/R2 triple, the bytes, then a pad byte if the length is odd.
    """
    if not data:
        raise ValueError("an LZX block must carry at least one byte")
    w = BitWriter()
    if intel_filesize:
        w.put(1, 1)
        w.put(intel_filesize >> 16, 16)
        w.put(intel_filesize & 0xFFFF, 16)
    else:
        w.put(0, 1)
    w.put(3, 3)
    w.put(len(data), 24)
    w.align_word()
    out = bytes(w.out) + struct.pack("<III", 1, 1, 1) + bytes(data)
    if len(data) & 1:
        out += b"\0"
    return out


def ce_compress_blob(data, window_bits=15, block_size=4096):
    """Wrap `data` as a Windows CE CECompress blob (what CEDecompressROM reads).

    Header: a table of 3-byte little-endian values. [0] is the total decoded
    size; [1..n-1] are the END offsets of each compressed block. Each block is
    u32 window bits, u32 decoded size, 8 reserved bytes, then an LZX stream.
    """
    chunks = [data[i:i + block_size] for i in range(0, len(data), block_size)] or [b""]
    blocks = [struct.pack("<II", window_bits, len(c)) + bytes(8) + lzx_stored_stream(c)
              for c in chunks]
    nblocks = len(blocks) + 1          # entry 0 is the size, not a block
    table_end = nblocks * 3
    ends, pos = [], table_end
    for b in blocks:
        pos += len(b)
        ends.append(pos)
    u24 = lambda v: struct.pack("<I", v)[:3]
    return b"".join([u24(len(data))] + [u24(e) for e in ends] + blocks)
