#!/usr/bin/env python3
"""Hand-built ReiserFS images for the extraction regression.

ReiserFS has no populate-from-directory mkfs mode and the kernel driver was
removed in 6.13, so a real round-trip image cannot be produced unprivileged.
Instead we assemble images byte-for-byte from the on-disk layout, modeled on
exactly what mkreiserfs 3.6/3.5 writes (verified against debugreiserfs output):

  - superblock at 64 KiB (3.6, magic "ReIsEr2Fs") or 8 KiB (3.5, "ReIsErFs");
  - an S+ tree of formatted blocks: internal nodes (level > 1) = block header +
    N keys + N+1 disk_child pointers; leaves (level 1) = block header + N item
    headers at the front + item bodies packed at the back;
  - per-item key format via ih_version (0 = v1 offset+uniqueness, 1 = v2 60-bit
    offset + 4-bit type), matching the real images where a 3.6 object mixes a v2
    stat-data item with a v1 directory item;
  - objects keyed (dir_id, objectid); a child's dir_id is its parent's objectid.

Everything is little-endian and packed. Block numbers count from the partition
start (block 0), and block N is at base + N*block_size.
"""
import struct

BS = 4096  # block size used by both images

# Item type values (v2 key top-nibble; v1 maps through the uniqueness field).
T_SD, T_INDIRECT, T_DIRECT, T_DIRENTRY = 0, 1, 2, 3
V1_UNIQ = {T_SD: 0, T_DIRENTRY: 500, T_INDIRECT: 0xFFFFFFFE, T_DIRECT: 0xFFFFFFFF}

S_IFDIR, S_IFREG, S_IFLNK = 0o040000, 0o100000, 0o120000


def key(dir_id, objectid, offset, itype, v2):
    """16-byte on-disk key."""
    k = struct.pack("<II", dir_id, objectid)
    if v2:
        return k + struct.pack("<Q", (itype << 60) | (offset & ((1 << 60) - 1)))
    return k + struct.pack("<II", offset, V1_UNIQ[itype])


def item_head(dir_id, objectid, offset, itype, v2, ilen, iloc, u16=0):
    """24-byte item header. `u16` is entry count (directories) else free/0."""
    ver = 1 if v2 else 0
    return key(dir_id, objectid, offset, itype, v2) + struct.pack("<HHHH", u16, ilen, iloc, ver)


def sd_v2(mode, size):
    b = bytearray(44)
    struct.pack_into("<H", b, 0, mode)        # sd_mode
    struct.pack_into("<I", b, 4, 1)           # sd_nlink
    struct.pack_into("<Q", b, 8, size)        # sd_size
    struct.pack_into("<I", b, 36, (size + BS - 1) // BS)  # sd_blocks (cosmetic)
    return bytes(b)


def sd_v1(mode, size):
    b = bytearray(32)
    struct.pack_into("<H", b, 0, mode)        # sd_mode
    struct.pack_into("<H", b, 2, 1)           # sd_nlink
    struct.pack_into("<I", b, 8, size)        # sd_size
    struct.pack_into("<I", b, 28, 0xFFFFFFFF)  # sd_first_direct_byte (no tail marker)
    return bytes(b)


def dir_body(entries, pad8):
    """entries: list of (name, child_dir_id, child_objectid). Returns (body, count).

    deh array at the front; names packed toward the end so entry[0] takes the
    highest location (as mkreiserfs lays them out). With pad8 each name slot is
    rounded up to 8 bytes (3.6 style); otherwise names are tight (3.5 style).
    """
    n = len(entries)
    slots = []
    for name, _, _ in entries:
        raw = name.encode()
        if pad8:
            raw = raw + b"\x00" * ((-len(raw)) % 8)  # trailing-NUL pad to a multiple of 8
        slots.append(raw)
    # Place names in reverse entry order: entry[n-1] lowest address, entry[0] highest.
    names_area = bytearray()
    locations = [0] * n
    cursor = n * 16
    for i in range(n - 1, -1, -1):
        locations[i] = cursor
        names_area += slots[i]
        cursor += len(slots[i])
    dehs = bytearray()
    for i, (name, cdir, cobj) in enumerate(entries):
        # deh_offset (hash; any increasing value works), dir_id, objectid, loc, state=visible(4)
        dehs += struct.pack("<IIIHH", i + 1, cdir, cobj, locations[i], 4)
    body = bytes(dehs) + bytes(names_area)
    return body, n


def leaf(items, level=1):
    """items: list of (item_head_fields, body) where item_head_fields is a dict.

    Returns a BS-sized leaf block. Bodies are packed at the end; headers follow
    the block header. Each item dict: dir_id,objectid,offset,itype,v2,u16.
    """
    b = bytearray(BS)
    nr = len(items)
    # bodies packed from the end
    cursor = BS
    placed = []
    for fields, body in items:
        cursor -= len(body)
        b[cursor:cursor + len(body)] = body
        placed.append((fields, len(body), cursor))
    # block header
    free = cursor - (24 + nr * 24)
    struct.pack_into("<HHHH", b, 0, level, nr, max(free, 0), 0)
    # item headers
    off = 24
    for fields, ilen, iloc in placed:
        ih = item_head(fields["dir_id"], fields["objectid"], fields["offset"],
                       fields["itype"], fields["v2"], ilen, iloc, fields.get("u16", 0))
        b[off:off + 24] = ih
        off += 24
    return bytes(b)


def internal(child_blocks, level=2):
    """A one-key internal node pointing at child_blocks (>=2). Keys are ignored
    by the extractor (it follows every child), so the separating key is zeros."""
    b = bytearray(BS)
    nr = len(child_blocks) - 1
    struct.pack_into("<HHHH", b, 0, level, nr, 0, 0)
    off = 24
    for _ in range(nr):
        b[off:off + 16] = b"\x00" * 16  # separating key (unused by extractor)
        off += 16
    for blk in child_blocks:
        b[off:off + 8] = struct.pack("<IHH", blk, 0, 0)  # disk_child
        off += 8
    return bytes(b)


def superblock(block_count, root_block, magic, tree_height):
    b = bytearray(BS)
    struct.pack_into("<I", b, 0, block_count)   # s_block_count
    struct.pack_into("<I", b, 8, root_block)    # s_root_block
    struct.pack_into("<H", b, 44, BS)           # s_blocksize
    b[52:52 + len(magic)] = magic               # s_magic
    struct.pack_into("<H", b, 68, tree_height)  # s_tree_height
    return bytes(b)


def place(img, blk, data):
    off = blk * BS
    img[off:off + len(data)] = data


def build_36():
    """3.6 image: 2-level tree (internal root + 2 leaves), SD/body items v2,
    directory items v1, NUL-padded names. Exercises internal-node traversal,
    indirect items, a tail, a leading hole, a symlink, and a nested dir.

    Returns (image_bytes, expected) where expected maps relpath -> descriptor
    matching tests/test_extract.py's tree_manifest format."""
    nblocks = 64
    img = bytearray(nblocks * BS)
    SB, ROOT, LEAFA, LEAFB = 16, 17, 18, 19
    DA, DB, DD = 20, 21, 22  # data blocks

    blkA = bytes([0xA5]) * BS
    blkB = bytes(range(256)) * 16          # 4096 bytes, known pattern
    blkD = bytes([0x5A]) * BS
    tail = b"TAILDATA" * 12 + b"X" * 4      # 100 bytes
    place(img, DA, blkA)
    place(img, DB, blkB)
    place(img, DD, blkD)

    big = blkA + blkB + tail               # 8292 bytes
    sparse = (b"\x00" * BS) + blkD         # 8192 bytes, leading hole

    V2 = True
    # Objects: root(1,2); small(2,3); big(2,4); sparse(2,5); link(2,6); sub(2,7); nested(7,8)
    root_entries = [(".", 1, 2), ("..", 0, 1), ("small.txt", 2, 3), ("big.bin", 2, 4),
                    ("sparse.bin", 2, 5), ("link", 2, 6), ("sub", 2, 7)]
    sub_entries = [(".", 2, 7), ("..", 1, 2), ("nested.txt", 7, 8)]
    rbody, rcnt = dir_body(root_entries, pad8=True)
    sbody, scnt = dir_body(sub_entries, pad8=True)

    # Leaf A: root SD + root dir item + small SD/direct + big SD/indirect/tail
    leafA_items = [
        ({"dir_id": 1, "objectid": 2, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFDIR | 0o755, len(rbody))),
        ({"dir_id": 1, "objectid": 2, "offset": 1, "itype": T_DIRENTRY, "v2": False, "u16": rcnt}, rbody),
        ({"dir_id": 2, "objectid": 3, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFREG | 0o644, 6)),
        ({"dir_id": 2, "objectid": 3, "offset": 1, "itype": T_DIRECT, "v2": V2}, b"hello\n"),
        ({"dir_id": 2, "objectid": 4, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFREG | 0o644, len(big))),
        ({"dir_id": 2, "objectid": 4, "offset": 1, "itype": T_INDIRECT, "v2": V2}, struct.pack("<II", DA, DB)),
        ({"dir_id": 2, "objectid": 4, "offset": 2 * BS + 1, "itype": T_DIRECT, "v2": V2}, tail),
    ]
    # Leaf B: sparse SD/indirect(hole) + link SD/direct + sub SD/dir + nested SD/direct
    leafB_items = [
        ({"dir_id": 2, "objectid": 5, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFREG | 0o644, len(sparse))),
        ({"dir_id": 2, "objectid": 5, "offset": 1, "itype": T_INDIRECT, "v2": V2}, struct.pack("<II", 0, DD)),
        ({"dir_id": 2, "objectid": 6, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFLNK | 0o777, len("small.txt"))),
        ({"dir_id": 2, "objectid": 6, "offset": 1, "itype": T_DIRECT, "v2": V2}, b"small.txt"),
        ({"dir_id": 2, "objectid": 7, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFDIR | 0o755, len(sbody))),
        ({"dir_id": 2, "objectid": 7, "offset": 1, "itype": T_DIRENTRY, "v2": False, "u16": scnt}, sbody),
        ({"dir_id": 7, "objectid": 8, "offset": 0, "itype": T_SD, "v2": V2}, sd_v2(S_IFREG | 0o644, len("nested\n"))),
        ({"dir_id": 7, "objectid": 8, "offset": 1, "itype": T_DIRECT, "v2": V2}, b"nested\n"),
    ]
    place(img, SB, superblock(nblocks, ROOT, b"ReIsEr2Fs", 3))
    place(img, ROOT, internal([LEAFA, LEAFB], level=2))
    place(img, LEAFA, leaf(leafA_items))
    place(img, LEAFB, leaf(leafB_items))

    import hashlib
    h = lambda d: hashlib.sha256(d).hexdigest()
    expected = {
        "small.txt": ("file", h(b"hello\n")),
        "big.bin": ("file", h(big)),
        "sparse.bin": ("file", h(sparse)),
        "link": ("link", "small.txt"),
        "sub": ("dir",),
        "sub/nested.txt": ("file", h(b"nested\n")),
    }
    return bytes(img), expected


def build_35():
    """3.5 image: single-leaf tree, all items v1 (SD v1, 32 bytes), tight names,
    superblock at 8 KiB. Exercises the all-old-format path and the 8 KiB base."""
    nblocks = 32
    img = bytearray(nblocks * BS)
    SB, ROOT = 2, 3  # 3.5 superblock at 8 KiB -> block 2

    root_entries = [(".", 1, 2), ("..", 0, 1), ("file.txt", 2, 3), ("d", 2, 4)]
    d_entries = [(".", 2, 4), ("..", 1, 2), ("inner.bin", 4, 5)]
    rbody, rcnt = dir_body(root_entries, pad8=False)
    dbody, dcnt = dir_body(d_entries, pad8=False)
    inner = b"inner-content-0123456789\n"

    items = [
        ({"dir_id": 1, "objectid": 2, "offset": 0, "itype": T_SD, "v2": False}, sd_v1(S_IFDIR | 0o755, len(rbody))),
        ({"dir_id": 1, "objectid": 2, "offset": 1, "itype": T_DIRENTRY, "v2": False, "u16": rcnt}, rbody),
        ({"dir_id": 2, "objectid": 3, "offset": 0, "itype": T_SD, "v2": False}, sd_v1(S_IFREG | 0o600, len(b"abc\n"))),
        ({"dir_id": 2, "objectid": 3, "offset": 1, "itype": T_DIRECT, "v2": False}, b"abc\n"),
        ({"dir_id": 2, "objectid": 4, "offset": 0, "itype": T_SD, "v2": False}, sd_v1(S_IFDIR | 0o755, len(dbody))),
        ({"dir_id": 2, "objectid": 4, "offset": 1, "itype": T_DIRENTRY, "v2": False, "u16": dcnt}, dbody),
        ({"dir_id": 4, "objectid": 5, "offset": 0, "itype": T_SD, "v2": False}, sd_v1(S_IFREG | 0o644, len(inner))),
        ({"dir_id": 4, "objectid": 5, "offset": 1, "itype": T_DIRECT, "v2": False}, inner),
    ]
    place(img, SB, superblock(nblocks, ROOT, b"ReIsErFs", 2))
    place(img, ROOT, leaf(items))

    import hashlib
    h = lambda d: hashlib.sha256(d).hexdigest()
    expected = {
        "file.txt": ("file", h(b"abc\n")),
        "d": ("dir",),
        "d/inner.bin": ("file", h(inner)),
    }
    return bytes(img), expected


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "36"
    img, exp = (build_36() if which == "36" else build_35())
    out = sys.argv[2] if len(sys.argv) > 2 else f"synth{which}.img"
    with open(out, "wb") as f:
        f.write(img)
    print(f"wrote {out} ({len(img)} bytes); expected {len(exp)} entries")
