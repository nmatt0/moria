#!/usr/bin/env python3
"""Synthesize small HFS+ images that exercise the extractor's edge cases.

Hermetic and deterministic: no mkfs, no mount, no privilege. Each image is a
hand-built Volume Header + Catalog B-tree (+ Extents Overflow B-tree where a fork
is fragmented), with real data blocks the extents point at, so `moria -e` can
reconstruct and the test can byte-compare.

Structures (all big-endian):
  Volume Header @1024: sig 'H+', blockSize, totalBlocks, special-file forks
    (extentsOverflowFile @+192, catalogFile @+272).
  B-tree node: 14-byte BTNodeDescriptor (fLink, bLink, kind, height, numRecords),
    records packed from offset 14, and a backward-growing u16 offset array at the
    node end (numRecords+1 entries: each record start, then the free offset).
  Catalog leaf record: HFSPlusCatalogKey {keyLength, parentID, name len+UTF-16BE}
    then a folder(1) or file(2) body. File body carries dataFork @+88 and
    resourceFork @+168 (HFSPlusForkData: logicalSize, clumpSize, totalBlocks, 8
    extents), ownerFlags @+41, fileMode @+42.
  Extents Overflow leaf record: HFSPlusExtentKey {keyLength=10, forkType, pad,
    fileID, startBlock} then 8 extents.

This module is imported by test_hfsplus_extract.py, which knows the expected
contents by name. No external filesystem's names or data appear here.
"""
import struct

BLOCK = 512
NODE = 4096

ROOT_CNID = 2
S_IFREG = 0o100644
S_IFLNK = 0o120777
UF_COMPRESSED = 0x20
FORK_DATA = 0x00


def _utf16be(s: str) -> bytes:
    return s.encode("utf-16-be")


def _catalog_key(parent: int, name: str) -> bytes:
    name16 = _utf16be(name)
    name_len = len(name16) // 2
    body = struct.pack(">IH", parent, name_len) + name16
    key_len = len(body)  # bytes after the keyLength field
    return struct.pack(">H", key_len) + body


def _fork_data(logical: int, extents) -> bytes:
    """HFSPlusForkData: logicalSize(u64), clumpSize(u32), totalBlocks(u32), 8 extents."""
    total_blocks = sum(c for _, c in extents)
    out = struct.pack(">QII", logical, 0, total_blocks)
    ext = list(extents) + [(0, 0)] * (8 - len(extents))
    for start, count in ext[:8]:
        out += struct.pack(">II", start, count)
    return out


def _file_record(cnid: int, mode: int, data_logical: int, data_extents,
                 rsrc_logical: int = 0, owner_flags: int = 0) -> bytes:
    b = bytearray(248)
    struct.pack_into(">H", b, 0, 2)        # recordType = file
    struct.pack_into(">I", b, 8, cnid)     # fileID
    b[41] = owner_flags                     # ownerFlags (UF_COMPRESSED lives here)
    struct.pack_into(">H", b, 42, mode)    # fileMode
    b[88:88 + 80] = _fork_data(data_logical, data_extents)        # dataFork
    b[168:168 + 80] = _fork_data(rsrc_logical, [])               # resourceFork (size only)
    return bytes(b)


def _folder_record(cnid: int) -> bytes:
    b = bytearray(88)
    struct.pack_into(">H", b, 0, 1)        # recordType = folder
    struct.pack_into(">I", b, 8, cnid)     # folderID
    return bytes(b)


def _leaf_node(records, flink: int = 0) -> bytes:
    """Pack catalog/extents records into one leaf node (kind = -1)."""
    node = bytearray(NODE)
    struct.pack_into(">I", node, 0, flink)          # fLink
    struct.pack_into(">b", node, 8, -1)             # kind = kBTLeafNode
    struct.pack_into(">H", node, 10, len(records))  # numRecords
    offsets = []
    pos = 14
    for rec in records:
        offsets.append(pos)
        node[pos:pos + len(rec)] = rec
        pos += len(rec)
    offsets.append(pos)  # free-space offset
    # offset array grows backward from the node end: entry i at NODE-2*(i+1).
    for i, off in enumerate(offsets):
        struct.pack_into(">H", node, NODE - 2 * (i + 1), off)
    return bytes(node)


def _header_node(first_leaf: int, total_nodes: int) -> bytes:
    """B-tree header node (node 0). Only firstLeaf and nodeSize are read back."""
    node = bytearray(NODE)
    struct.pack_into(">b", node, 8, 1)              # kind = kBTHeaderNode
    # BTHeaderRec starts at offset 14.
    struct.pack_into(">I", node, 14 + 10, first_leaf)   # firstLeafNode
    struct.pack_into(">I", node, 14 + 14, first_leaf)   # lastLeafNode
    struct.pack_into(">H", node, 14 + 18, NODE)         # nodeSize
    struct.pack_into(">I", node, 14 + 22, total_nodes)  # totalNodes
    return bytes(node)


def _extent_overflow_record(fork_type: int, file_id: int, start_block: int, extents) -> bytes:
    key = struct.pack(">HBBII", 10, fork_type, 0, file_id, start_block)  # keyLength=10 + key
    ext = list(extents) + [(0, 0)] * (8 - len(extents))
    data = b"".join(struct.pack(">II", s, c) for s, c in ext[:8])
    return key + data


class Builder:
    def __init__(self, total_blocks=512):
        self.total_blocks = total_blocks
        self.img = bytearray(total_blocks * BLOCK)
        self.next_data_block = 64  # data region; metadata lives below this
        self.cat_records = []
        self.ovf_records = []
        self.expect = {}  # output relative path -> expected bytes (None = dir/compressed-empty)

    def _put_blocks(self, data: bytes):
        """Write data into fresh contiguous blocks, return (start_block, count)."""
        nblocks = (len(data) + BLOCK - 1) // BLOCK
        start = self.next_data_block
        self.img[start * BLOCK:start * BLOCK + len(data)] = data
        self.next_data_block += nblocks
        return start, nblocks

    def _put_scattered(self, chunks):
        """Write each 1-block chunk to a non-adjacent block; return extent list in order."""
        extents = []
        for ch in chunks:
            start = self.next_data_block
            self.img[start * BLOCK:start * BLOCK + len(ch)] = ch
            self.next_data_block += 2  # leave a gap so extents never coalesce
            extents.append((start, 1))
        return extents

    def add_file(self, parent, name, content, outpath):
        start, n = self._put_blocks(content)
        rec = _catalog_key(parent, name) + _file_record(len(self.cat_records) + 16, S_IFREG,
                                                         len(content), [(start, n)])
        self.cat_records.append(rec)
        self.expect[outpath] = content

    def add_fragmented_file(self, parent, name, content, outpath, inline=8, overflow=2):
        """Data split into 1-block extents: `inline` in the record, `overflow` in the tree."""
        cnid = len(self.cat_records) + 16
        chunks = [content[i:i + BLOCK] for i in range(0, len(content), BLOCK)]
        assert len(chunks) == inline + overflow, (len(chunks), inline, overflow)
        extents = self._put_scattered(chunks)
        inline_ext = extents[:inline]
        over_ext = extents[inline:]
        rec = _catalog_key(parent, name) + _file_record(cnid, S_IFREG, len(content), inline_ext)
        self.cat_records.append(rec)
        # overflow record keyed by the fork-relative start block (== inline block count)
        self.ovf_records.append(_extent_overflow_record(FORK_DATA, cnid, inline, over_ext))
        self.expect[outpath] = content

    def add_compressed_file(self, parent, name, outpath):
        """UF_COMPRESSED with an empty data fork (decmpfs): extracts as an empty file."""
        rec = _catalog_key(parent, name) + _file_record(len(self.cat_records) + 16, S_IFREG,
                                                         0, [], owner_flags=UF_COMPRESSED)
        self.cat_records.append(rec)
        self.expect[outpath] = b""

    def add_resource_fork_file(self, parent, name, content, outpath, rsrc_logical=4096):
        start, n = self._put_blocks(content)
        rec = _catalog_key(parent, name) + _file_record(len(self.cat_records) + 16, S_IFREG,
                                                         len(content), [(start, n)],
                                                         rsrc_logical=rsrc_logical)
        self.cat_records.append(rec)
        self.expect[outpath] = content

    def add_dir(self, parent, name, outpath):
        cnid = len(self.cat_records) + 16
        rec = _catalog_key(parent, name) + _folder_record(cnid)
        self.cat_records.append(rec)
        if outpath is not None:
            self.expect[outpath] = None
        return cnid

    def build(self) -> bytes:
        # Volume Header @1024.
        struct.pack_into(">H", self.img, 1024 + 0, 0x482B)       # 'H+'
        struct.pack_into(">H", self.img, 1024 + 2, 4)            # version
        struct.pack_into(">I", self.img, 1024 + 40, BLOCK)       # blockSize
        struct.pack_into(">I", self.img, 1024 + 44, self.total_blocks)

        # Catalog B-tree: header node (0) + one leaf node (1).
        cat = _header_node(1, 2) + _leaf_node(self.cat_records)
        cat_start, cat_blocks = self._put_blocks(cat)
        self.img[1024 + 272:1024 + 272 + 80] = _fork_data(len(cat), [(cat_start, cat_blocks)])

        # Extents Overflow B-tree (only if something is fragmented).
        if self.ovf_records:
            ovf = _header_node(1, 2) + _leaf_node(self.ovf_records)
            ovf_start, ovf_blocks = self._put_blocks(ovf)
            self.img[1024 + 192:1024 + 192 + 80] = _fork_data(len(ovf), [(ovf_start, ovf_blocks)])
        return bytes(self.img)


def _pattern(n: int, seed: int) -> bytes:
    return bytes(((i * 31 + seed * 7 + 11) & 0xFF) for i in range(n))


def full_image():
    """One image exercising every fix. Returns (image_bytes, {outpath: expected})."""
    b = Builder(total_blocks=512)
    # 1. ordinary file (control: must stay byte-identical)
    b.add_file(ROOT_CNID, "hello.txt", b"Hello, HFS+!\n", "hello.txt")
    # 2. file fragmented past the 8 inline extents (needs the overflow tree)
    frag = _pattern(10 * BLOCK, 1)
    b.add_fragmented_file(ROOT_CNID, "frag.bin", frag, "frag.bin", inline=8, overflow=2)
    # 3. file whose HFS+ name contains '/' (POSIX ':') -> written as ':', not dropped
    b.add_file(ROOT_CNID, "a/b.txt", b"slash-in-name\n", "a:b.txt")
    # 4. decmpfs-compressed file (empty data fork) -> empty output + warning
    b.add_compressed_file(ROOT_CNID, "compressed.bin", "compressed.bin")
    # 5. file carrying a resource fork -> content intact + warning
    b.add_resource_fork_file(ROOT_CNID, "withrsrc.bin", b"data-fork-stays\n", "withrsrc.bin")
    # 6. subdirectory recursion (control)
    sub = b.add_dir(ROOT_CNID, "sub", "sub")
    b.add_file(sub, "child.txt", b"nested file\n", "sub/child.txt")
    # 7. directory whose name contains '/': its whole subtree must survive
    slashdir = b.add_dir(ROOT_CNID, "weird/dir", "weird:dir")
    b.add_file(slashdir, "inside.txt", b"subtree preserved\n", "weird:dir/inside.txt")
    return b.build(), b.expect


def main():
    import sys
    img, expect = full_image()
    out = sys.argv[1] if len(sys.argv) > 1 else "hfsplus_extract.img"
    with open(out, "wb") as f:
        f.write(img)
    print(f"wrote {out} ({len(img)} bytes); {len(expect)} expected entries")


if __name__ == "__main__":
    main()
