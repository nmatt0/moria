#!/usr/bin/env python3
"""LZX stream writers, shared by the CE ROM and CAB regression tests.

Two writers live here:

  * `lzx_stored_stream` emits a single *uncompressed* block. It is enough to
    test the framings wrapped around LZX, and it is all the tests used to cover.
  * `lzx_compress` is a real compressor: canonical Huffman main/length/aligned
    trees, pretree-coded length deltas, LZ77 matches with the repeated-offset
    slots, the x86 filter, and the 16-bit pad that CAB writes at the end of
    every 32 KiB output frame. Without it the verbatim/aligned decoder -- the
    path every real cabinet takes -- is never exercised at all.

Streams from `lzx_compress` have been checked against libmspack, so they are
independent of moria's own reading of the format.

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


def ce_compress_blob(data, window_bits=15, block_size=4096, compress=False):
    """Wrap `data` as a Windows CE CECompress blob (what CEDecompressROM reads).

    Header: a table of 3-byte little-endian values. [0] is the total decoded
    size; [1..n-1] are the END offsets of each compressed block. Each block is
    u32 window bits, u32 decoded size, 8 reserved bytes, then an LZX stream.

    With `compress`, each block carries a real Huffman-coded LZX stream instead
    of a stored one; a CE block never reaches 32 KiB, so it is a single frame.
    """
    chunks = [data[i:i + block_size] for i in range(0, len(data), block_size)] or [b""]

    def stream(c):
        if not compress or not c:
            return lzx_stored_stream(c)
        frames = lzx_compress(c, window_bits=window_bits)
        assert len(frames) == 1, "a CE block is under one LZX frame"
        return frames[0]

    blocks = [struct.pack("<II", window_bits, len(c)) + bytes(8) + stream(c)
              for c in chunks]
    nblocks = len(blocks) + 1          # entry 0 is the size, not a block
    table_end = nblocks * 3
    ends, pos = [], table_end
    for b in blocks:
        pos += len(b)
        ends.append(pos)
    u24 = lambda v: struct.pack("<I", v)[:3]
    return b"".join([u24(len(data))] + [u24(e) for e in ends] + blocks)


# --- a real LZX compressor: Huffman trees, matches, CAB frame padding ---

LZX_FRAME = 32768
MIN_MATCH, MAX_MATCH = 2, 257
NUM_CHARS, NUM_PRIMARY_LENGTHS = 256, 7
POSITION_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}
EXTRA_BITS = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
              10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16] + [17] * 15
POSITION_BASE = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256,
                 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288,
                 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144,
                 393216, 524288, 655360, 786432, 917504, 1048576, 1179648, 1310720,
                 1441792, 1572864, 1703936, 1835008, 1966080, 2097152]
BLOCK_VERBATIM, BLOCK_ALIGNED = 1, 2


def package_merge(freqs, limit):
    """Length-limited Huffman code lengths. freqs: {sym: weight>0}."""
    used = sorted(freqs.items(), key=lambda kv: (kv[1], kv[0]))
    n = len(used)
    if n == 0:
        return {}
    if n == 1:
        return {used[0][0]: 1}
    coins = [(w, (s,)) for s, w in used]
    coins.sort(key=lambda t: t[0])
    result = list(coins)
    for _ in range(limit - 1):
        packaged = [(result[i][0] + result[i + 1][0], result[i][1] + result[i + 1][1])
                    for i in range(0, len(result) - 1, 2)]
        result = sorted(coins + packaged, key=lambda t: t[0])
    lengths = {s: 0 for s, _ in used}
    for _, syms in result[: 2 * n - 2]:
        for s in syms:
            lengths[s] += 1
    return lengths


def code_lengths(freqs, nsyms, limit=16):
    """Code lengths over [0, nsyms), always a *complete* code (LZX requires it)."""
    lengths = [0] * nsyms
    got = package_merge({s: w for s, w in freqs.items() if w > 0}, limit)
    for s, ln in got.items():
        lengths[s] = ln
    used = [s for s in range(nsyms) if lengths[s]]
    if len(used) == 1:
        # A lone 1-bit code is an incomplete table; pair it with a filler symbol.
        filler = next(s for s in range(nsyms) if s != used[0])
        lengths[used[0]] = lengths[filler] = 1
    return lengths


def canonical(lengths):
    codes, code = {}, 0
    for bl in range(1, 17):
        for sym in (s for s, ln in enumerate(lengths) if ln == bl):
            codes[sym] = code
            code += 1
        code <<= 1
    return codes


def write_lengths(w, lengths, prev, first, last):
    """Emit the pretree and the mod-17 length deltas for lengths[first:last]."""
    deltas = [(prev[x] - lengths[x]) % 17 for x in range(first, last)]
    freqs = {}
    for d in deltas:
        freqs[d] = freqs.get(d, 0) + 1
    pre_len = code_lengths(freqs, 20, limit=15)  # the length field is 4 bits
    pre_code = canonical(pre_len)
    for x in range(20):
        w.put(pre_len[x], 4)
    for d in deltas:
        w.put(pre_code[d], pre_len[d])


def apply_e8_forward(data, filesize, frame=LZX_FRAME):
    """The encoder-side x86 filter: the exact inverse of the decoder's pass."""
    out = bytearray(data)
    for base in range(0, len(out), frame):
        flen = min(frame, len(out) - base)
        if flen <= 10:
            continue
        i, curpos, limit = 0, base, flen - 10
        while i < limit:
            if out[base + i] != 0xE8:
                i += 1
                curpos += 1
                continue
            off = base + i + 1
            rel = struct.unpack("<i", bytes(out[off:off + 4]))[0]
            if -curpos <= rel < filesize:
                absv = rel + curpos if rel < filesize - curpos else rel - filesize
                out[off:off + 4] = struct.pack("<i", absv)
            i += 5
            curpos += 5
    return bytes(out)


def _tokenize(data, start, end, window):
    """Greedy match finder. Tokens never straddle a 32 KiB frame boundary."""
    tokens, index, pos = [], {}, start
    while pos < end:
        frame_end = min(end, (pos // LZX_FRAME + 1) * LZX_FRAME)
        best_len, best_off = 0, 0
        if pos + 3 <= end:
            key = data[pos:pos + 3]
            for cand in reversed(index.get(key, ())[-24:]):
                off = pos - cand
                if off < 1 or off > window:
                    continue
                n = 0
                cap = min(MAX_MATCH, frame_end - pos)
                while n < cap and data[cand + n] == data[pos + n]:
                    n += 1
                if n > best_len:
                    best_len, best_off = n, off
                    if n == cap:
                        break
        if best_len >= MIN_MATCH + 1:
            tokens.append((best_off, best_len))
            step = best_len
        else:
            tokens.append((0, data[pos]))
            step = 1
        for k in range(pos, min(pos + step, end - 2)):
            index.setdefault(data[k:k + 3], []).append(k)
        pos += step
    return tokens


def _emit_block(w, data, start, end, window_bits, aligned, prev_main, prev_len, on_frame):
    """Emit one block. `on_frame(pos)` runs each time output crosses a frame edge."""
    main_elements = NUM_CHARS + POSITION_SLOTS[window_bits] * 8
    window = 1 << window_bits
    tokens = _tokenize(data, start, end, window)

    # Resolve each token into its symbols, then count them to build the trees.
    plan, main_f, len_f, align_f = [], {}, {}, {}
    r0 = r1 = r2 = 1
    for off, val in tokens:
        if off == 0:
            plan.append(("lit", val, 1))
            main_f[val] = main_f.get(val, 0) + 1
            continue
        mlen = val - MIN_MATCH
        header = min(mlen, NUM_PRIMARY_LENGTHS)
        footer = mlen - NUM_PRIMARY_LENGTHS if header == NUM_PRIMARY_LENGTHS else None
        if off == r0:
            slot, extra_val = 0, None
        else:
            fo = off + 2
            slot = max(s for s in range(3, len(POSITION_BASE)) if POSITION_BASE[s] <= fo)
            extra_val = fo - POSITION_BASE[slot]
            r2, r1, r0 = r1, r0, off
        sym = NUM_CHARS + (slot << 3) + header
        main_f[sym] = main_f.get(sym, 0) + 1
        if footer is not None:
            len_f[footer] = len_f.get(footer, 0) + 1
        if extra_val is not None and aligned and EXTRA_BITS[slot] >= 3:
            align_f[extra_val & 7] = align_f.get(extra_val & 7, 0) + 1
        plan.append(("match", sym, footer, slot, extra_val, val))

    main_len = code_lengths(main_f, main_elements)
    lens_len = code_lengths(len_f, 249)
    main_code, lens_code = canonical(main_len), canonical(lens_len)
    align_len = [3] * 8
    align_code = canonical(align_len)

    w.put(BLOCK_ALIGNED if aligned else BLOCK_VERBATIM, 3)
    w.put(end - start, 24)
    if aligned:
        for x in range(8):
            w.put(align_len[x], 3)
    write_lengths(w, main_len, prev_main, 0, NUM_CHARS)
    write_lengths(w, main_len, prev_main, NUM_CHARS, main_elements)
    write_lengths(w, lens_len, prev_len, 0, 249)

    pos = start
    for item in plan:
        if item[0] == "lit":
            s = item[1]
            w.put(main_code[s], main_len[s])
        else:
            _, sym, footer, slot, extra_val, _n = item
            w.put(main_code[sym], main_len[sym])
            if footer is not None:
                w.put(lens_code[footer], lens_len[footer])
            if extra_val is not None:
                nx = EXTRA_BITS[slot]
                if aligned and nx >= 3:
                    w.put(extra_val >> 3, nx - 3)
                    w.put(align_code[extra_val & 7], 3)
                elif nx:
                    w.put(extra_val, nx)
        pos += item[2] if item[0] == "lit" else item[5]
        if pos % LZX_FRAME == 0:
            on_frame(pos)
    return main_len, lens_len


def lzx_compress(data, window_bits=21, intel_filesize=0, block_ends=None,
                 aligned_blocks=()):
    """Compress `data` into per-32-KiB-frame chunks, CAB-style.

    The bitstream is padded to a 16-bit boundary at the end of every output
    frame, which is what lets a CAB decoder restart on each CFDATA block.
    """
    if intel_filesize:
        data = apply_e8_forward(data, intel_filesize)
    if block_ends is None:
        block_ends = [len(data)]
    assert block_ends and block_ends[-1] == len(data)

    w = BitWriter()
    w.put(1 if intel_filesize else 0, 1)
    if intel_filesize:
        w.put((intel_filesize >> 16) & 0xFFFF, 16)
        w.put(intel_filesize & 0xFFFF, 16)

    marks = []

    def on_frame(pos):
        if pos < len(data):
            w.align_word()
            marks.append(len(w.out))

    prev_main = [0] * (NUM_CHARS + POSITION_SLOTS[window_bits] * 8)
    prev_len = [0] * 249
    start = 0
    for bi, end in enumerate(block_ends):
        prev_main, prev_len = _emit_block(w, data, start, end, window_bits,
                                          bi in aligned_blocks, prev_main,
                                          prev_len, on_frame)
        start = end
    w.align_word()
    marks.append(len(w.out))

    blob = bytes(w.out)
    frames, prev = [], 0
    for m in marks:
        frames.append(blob[prev:m])
        prev = m
    return frames
