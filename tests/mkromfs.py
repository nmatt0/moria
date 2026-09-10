#!/usr/bin/env python3
"""Create small Linux romfs (rom1fs) files for tests.

Most systems do not include a romfs builder, so this tool lets
tests/test_extract.py create a folder tree, unpack it with moria, and compare the
result. The code below follows the romfs file layout exactly.

Usage: mkromfs.py <srcdir> <out.romfs>
"""
import os
import struct
import sys


def align16(x):
    return (x + 15) & ~15


class N:
    def __init__(self, name, typ, data=b"", children=None):
        self.name = name.encode() if isinstance(name, str) else name
        self.typ = typ  # 1=dir 2=regular 3=symlink 0=hardlink('.'/'..')
        self.data = data
        self.children = children
        self.off = 0
        self.spec = 0
        self._next = 0
        self._childlist = None


def scan_dir(path):
    """Return the folder's entries in the same order every time."""
    out = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if os.path.islink(full):
            out.append(N(name, 3, os.readlink(full).encode()))
        elif os.path.isdir(full):
            out.append(N(name, 1, children=scan_dir(full)))
        elif os.path.isfile(full):
            with open(full, "rb") as f:
                out.append(N(name, 2, f.read()))
    return out


def build(root_children, volname="rom"):
    order = []

    def flatten(children):
        lst = [N(".", 0), N("..", 0)] + children
        for n in lst:
            order.append(n)
        for n in children:
            if n.typ == 1:
                n._childlist = flatten(n.children)
        return lst

    rootlist = flatten(root_children)

    off = align16(16 + len(volname) + 1)
    for n in order:
        n.off = off
        data_start = align16(off + 16 + len(n.name) + 1)
        off = align16(data_start + len(n.data))
    total = off

    buf = bytearray(total)
    buf[0:8] = b"-rom1fs-"
    struct.pack_into(">I", buf, 8, total)
    struct.pack_into(">I", buf, 12, 0)  # checksum (extractors here don't require it)
    buf[16:16 + len(volname)] = volname.encode()

    def emit(lst, parent_off, self_off):
        lst[0].spec = self_off   # "."  -> this directory
        lst[1].spec = parent_off  # ".." -> parent
        for i, n in enumerate(lst):
            nxt = lst[i + 1].off if i + 1 < len(lst) else 0
            n._next = (nxt & ~0xF) | (n.typ & 7)
            if n.typ == 1 and n._childlist is not None:
                n.spec = n._childlist[0].off
        for n in lst:
            if n.typ == 1 and n._childlist is not None:
                emit(n._childlist, self_off, n.off)

    root_self = rootlist[0].off
    emit(rootlist, root_self, root_self)

    for n in order:
        o = n.off
        struct.pack_into(">I", buf, o + 0, n._next)
        struct.pack_into(">I", buf, o + 4, n.spec)
        struct.pack_into(">I", buf, o + 8, len(n.data))
        struct.pack_into(">I", buf, o + 12, 0)
        buf[o + 16:o + 16 + len(n.name)] = n.name
        d = align16(o + 16 + len(n.name) + 1)
        buf[d:d + len(n.data)] = n.data
    return bytes(buf)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    data = build(scan_dir(sys.argv[1]))
    with open(sys.argv[2], "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
