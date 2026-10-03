#!/usr/bin/env python3
"""Minimal compound-file (CFBF) writer, shared by the CFBF regression tests.

The point of the format, for moria, is that a stream is *not* contiguous: its
sectors are chained through a FAT and interleaved with everything else. So this
writer deliberately round-robins sectors between streams. A reader that walks
linearly from a stream's first sector gets the right bytes for exactly one
sector and garbage after it, which is the bug this fixture exists to catch.
"""
import struct

SECT = 512
MINI = 64
MINI_CUTOFF = 4096
FREE, ENDOFCHAIN, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_mangle(name):
    """Encode a name the way MSI encodes its stream names (two chars per unit)."""
    units, i = [], 0
    while i < len(name):
        if i + 1 < len(name):
            units.append(0x3800 + ALPHABET.index(name[i]) + (ALPHABET.index(name[i + 1]) << 6))
            i += 2
        else:
            units.append(0x4800 + ALPHABET.index(name[i]))
            i += 1
    return "".join(chr(u) for u in units)


def _chunks(data, size):
    return [data[i:i + size].ljust(size, b"\0") for i in range(0, len(data), size)] or []


def build(streams, interleave=True):
    """streams: list of (name, bytes). Returns the compound file."""
    big = [(n, d) for n, d in streams if len(d) >= MINI_CUTOFF]
    small = [(n, d) for n, d in streams if len(d) < MINI_CUTOFF]

    # The mini stream concatenates every small stream, 64 bytes per mini sector.
    mini_data, mini_index = b"", {}
    for n, d in small:
        mini_index[n] = len(mini_data) // MINI
        mini_data += b"".join(_chunks(d, MINI))

    n_dir_entries = 1 + len(streams)
    dir_sectors = (n_dir_entries * 128 + SECT - 1) // SECT
    mini_sectors = len(mini_data) // MINI
    minifat_sectors = ((mini_sectors * 4) + SECT - 1) // SECT if mini_sectors else 0
    ministream_sectors = (len(mini_data) + SECT - 1) // SECT

    # Every chain that needs real sectors, in allocation order.
    chains = [("dir", dir_sectors)]
    if minifat_sectors:
        chains.append(("minifat", minifat_sectors))
    if ministream_sectors:
        chains.append(("ministream", ministream_sectors))
    for n, d in big:
        chains.append((("big", n), (len(d) + SECT - 1) // SECT))

    total_payload = sum(c for _, c in chains)
    nfat = 1
    while nfat * (SECT // 4) < total_payload + nfat:
        nfat += 1

    # FAT sectors first, then the payload sectors -- round-robin across chains so
    # no stream is contiguous.
    alloc = {k: [] for k, _ in chains}
    nxt = nfat
    if interleave:
        remaining = {k: c for k, c in chains}
        while any(remaining.values()):
            for k, _ in chains:
                if remaining[k]:
                    alloc[k].append(nxt)
                    nxt += 1
                    remaining[k] -= 1
    else:
        for k, c in chains:
            for _ in range(c):
                alloc[k].append(nxt)
                nxt += 1

    total_sectors = nxt
    fat = [FREE] * (nfat * (SECT // 4))
    for i in range(nfat):
        fat[i] = FATSECT
    for k, _ in chains:
        s = alloc[k]
        for a, b in zip(s, s[1:]):
            fat[a] = b
        fat[s[-1]] = ENDOFCHAIN

    # Directory entries.
    def entry(name, typ, start, size, left=NOSTREAM, right=NOSTREAM, child=NOSTREAM):
        e = bytearray(128)
        u = name.encode("utf-16-le") + b"\0\0"
        e[:len(u)] = u
        struct.pack_into("<H", e, 0x40, len(u))
        e[0x42] = typ
        e[0x43] = 1
        struct.pack_into("<III", e, 0x44, left, right, child)
        struct.pack_into("<I", e, 0x74, start)
        struct.pack_into("<Q", e, 0x78, size)
        return bytes(e)

    # Root first, then one entry per stream chained as right siblings.
    entries = [entry("Root Entry", 5,
                     alloc["ministream"][0] if ministream_sectors else NOSTREAM,
                     len(mini_data), child=1)]
    for i, (n, d) in enumerate(streams):
        nxt_sib = (i + 2) if i + 1 < len(streams) else NOSTREAM
        if len(d) >= MINI_CUTOFF:
            start = alloc[("big", n)][0]
        else:
            start = mini_index[n]
        entries.append(entry(n, 2, start, len(d), right=nxt_sib))
    dir_bytes = b"".join(entries).ljust(dir_sectors * SECT, b"\0")

    minifat = []
    for n, d in small:
        base = mini_index[n]
        cnt = (len(d) + MINI - 1) // MINI
        for k in range(cnt - 1):
            minifat.append(base + k + 1)
        minifat.append(ENDOFCHAIN)
    minifat_bytes = struct.pack("<%dI" % len(minifat), *minifat) if minifat else b""
    minifat_bytes = minifat_bytes.ljust(minifat_sectors * SECT, b"\xff")

    # Lay the sectors down.
    body = bytearray(b"\0" * (total_sectors * SECT))

    def put(sector_list, blob):
        for i, s in enumerate(sector_list):
            body[s * SECT:(s + 1) * SECT] = blob[i * SECT:(i + 1) * SECT].ljust(SECT, b"\0")

    put(alloc["dir"], dir_bytes)
    if minifat_sectors:
        put(alloc["minifat"], minifat_bytes)
    if ministream_sectors:
        put(alloc["ministream"], mini_data.ljust(ministream_sectors * SECT, b"\0"))
    for n, d in big:
        put(alloc[("big", n)], d)
    fat_bytes = struct.pack("<%dI" % len(fat), *fat)
    for i in range(nfat):
        body[i * SECT:(i + 1) * SECT] = fat_bytes[i * SECT:(i + 1) * SECT]

    hdr = bytearray(b"\0" * SECT)
    hdr[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<HHHHH", hdr, 0x18, 0x003E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", hdr, 0x2C, nfat)
    struct.pack_into("<I", hdr, 0x30, alloc["dir"][0])
    struct.pack_into("<I", hdr, 0x38, MINI_CUTOFF)
    struct.pack_into("<I", hdr, 0x3C, alloc["minifat"][0] if minifat_sectors else ENDOFCHAIN)
    struct.pack_into("<I", hdr, 0x40, minifat_sectors)
    struct.pack_into("<I", hdr, 0x44, ENDOFCHAIN)
    struct.pack_into("<I", hdr, 0x48, 0)
    for i in range(109):
        struct.pack_into("<I", hdr, 0x4C + i * 4, i if i < nfat else FREE)
    return bytes(hdr) + bytes(body)


def build_deep_chain(n, payload=b"deep-chain-payload-" * 300):
    """A compound file whose directory is one linear chain of `n` stream entries
    (each entry's `left` points at the next), to exercise the extractor's
    directory walk against stack exhaustion. A crafted MSI can nest the sibling
    tree up to the 262144-entry cap deep; a recursive walk overflows the call
    stack on it. The deepest entry carries `payload` (>= the 4096 mini cutoff,
    so it lives in a regular FAT chain) and must come back byte-for-byte, which
    proves the walk actually reached the end of the chain rather than giving up.

    Uses 4096-byte sectors so even a large `n` needs only a handful of FAT
    sectors, which fit the 109 inline DIFAT slots (no DIFAT-sector chain).
    """
    ss = 1 << 12
    assert len(payload) >= MINI_CUTOFF

    def entry(name, typ, left, right, child, start, size):
        b = bytearray(128)
        u = name.encode("utf-16-le")[:62]
        b[:len(u)] = u
        struct.pack_into("<H", b, 0x40, len(u) + 2)   # name length incl NUL
        b[0x42] = typ
        struct.pack_into("<III", b, 0x44, left, right, child)
        struct.pack_into("<I", b, 0x74, start)
        struct.pack_into("<Q", b, 0x78, size)
        return bytes(b)

    dir_sectors = ((n + 1) * 128 + ss - 1) // ss
    pay_sectors = (len(payload) + ss - 1) // ss
    pay_start = dir_sectors                       # payload sits right after the directory

    # Root -> entry 1; entry i -> entry i+1 via `left`; the last carries payload.
    entries = [entry("Root Entry", 5, NOSTREAM, NOSTREAM, 1, ENDOFCHAIN, 0)]
    for i in range(1, n + 1):
        nxt = i + 1 if i < n else NOSTREAM
        if i == n:
            entries.append(entry("deep", 2, nxt, NOSTREAM, NOSTREAM, pay_start, len(payload)))
        else:
            entries.append(entry("s%d" % i, 2, nxt, NOSTREAM, NOSTREAM, ENDOFCHAIN, 0))
    dir_bytes = b"".join(entries).ljust(dir_sectors * ss, b"\0")

    # FAT: dir chain, payload chain, then the FAT sectors themselves (FATSECT).
    nfat = 1
    while True:
        total = dir_sectors + pay_sectors + nfat
        need = (total * 4 + ss - 1) // ss
        if need == nfat:
            break
        nfat = need
    fat_base = dir_sectors + pay_sectors
    fat = [FREE] * (fat_base + nfat)
    for i in range(dir_sectors):
        fat[i] = i + 1 if i + 1 < dir_sectors else ENDOFCHAIN
    for i in range(pay_sectors):
        fat[pay_start + i] = pay_start + i + 1 if i + 1 < pay_sectors else ENDOFCHAIN
    for i in range(nfat):
        fat[fat_base + i] = FATSECT
    fat_bytes = struct.pack("<%dI" % len(fat), *fat).ljust(nfat * ss, b"\xff")

    body = bytearray((fat_base + nfat) * ss)
    body[0:len(dir_bytes)] = dir_bytes
    body[pay_start * ss:pay_start * ss + len(payload)] = payload
    body[fat_base * ss:fat_base * ss + len(fat_bytes)] = fat_bytes

    hdr = bytearray(ss)
    hdr[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<HHHHH", hdr, 0x18, 0x003E, 4, 0xFFFE, 12, 6)  # major 4, 4096-byte sectors
    struct.pack_into("<I", hdr, 0x2C, nfat)
    struct.pack_into("<I", hdr, 0x30, 0)              # first dir sector
    struct.pack_into("<I", hdr, 0x38, MINI_CUTOFF)
    struct.pack_into("<I", hdr, 0x3C, ENDOFCHAIN)     # first minifat
    struct.pack_into("<I", hdr, 0x40, 0)
    struct.pack_into("<I", hdr, 0x44, ENDOFCHAIN)     # first difat
    struct.pack_into("<I", hdr, 0x48, 0)
    for i in range(109):
        struct.pack_into("<I", hdr, 0x4C + i * 4, fat_base + i if i < nfat else FREE)
    return bytes(hdr) + bytes(body)
