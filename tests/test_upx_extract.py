#!/usr/bin/env python3
"""UPX unpacking (extraction) round-trip: moria -e must reproduce `upx -d` output
byte-for-byte.

Self-skips cleanly when the `upx` tool is not installed. Packs a small host ELF
with every method (NRV2B/NRV2D/NRV2E/LZMA and --best), unpacks it two ways, and
requires moria's recovered file to be byte-identical to upx's own -d output. Also
checks a packed ELF embedded at a nonzero offset inside a larger blob, and that a
non-UPX ELF yields no unpacked output. Cross-arch packs (i386/arm64/...) run too
when a matching static toolchain is available, but their absence never fails the
test.

Exit nonzero on any real failure.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

METHODS = {
    "nrv2b": [],
    "nrv2d": ["--nrv2d"],
    "nrv2e": ["--nrv2e"],
    "lzma": ["--lzma"],
    "best": ["--best"],
}


def check(cond, msg, fails):
    if not cond:
        fails.append(msg)
    return cond


def upx_pack(upx, base, opt, out):
    r = subprocess.run([upx, "-q", "-f", *opt, "-o", out, base],
                       capture_output=True, timeout=120)
    return r.returncode == 0 and os.path.exists(out)


def upx_unpack_ref(upx, packed, out):
    r = subprocess.run([upx, "-q", "-d", "-o", out, packed],
                       capture_output=True, timeout=120)
    # upx -d can emit recovery warnings yet still fully recover; trust the file.
    return os.path.exists(out)


def moria_unpack(packed, workdir):
    outdir = os.path.join(workdir, "ext")
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    subprocess.run([MORIA, "-e", "-C", outdir, packed], capture_output=True, timeout=120)
    for root, _dirs, files in os.walk(outdir):
        if "unpacked.elf" in files:
            return os.path.join(root, "unpacked.elf")
    return None


def read(p):
    with open(p, "rb") as f:
        return f.read()


def one_pack(upx, base, label, opt, d, fails, embedded=False):
    packed = os.path.join(d, f"{label}.packed")
    if not upx_pack(upx, base, opt, packed):
        return  # this method/arch combo not producible; skip silently
    ref = os.path.join(d, f"{label}.ref")
    if not upx_unpack_ref(upx, packed, ref):
        return
    src = packed
    if embedded:
        # Embed the packed image at a nonzero offset with padding + trailing junk.
        blob = os.path.join(d, f"{label}.blob")
        with open(blob, "wb") as f:
            f.write(b"\x00" * 0x1000)
            f.write(read(packed))
            f.write(b"\xde\xad\xbe\xef" * 64)
        src = blob
    got = moria_unpack(src, d)
    if not check(got is not None, f"{label}{' (embedded)' if embedded else ''}: no unpacked output", fails):
        return
    check(read(got) == read(ref),
          f"{label}{' (embedded)' if embedded else ''}: moria -e != upx -d (not byte-exact)", fails)


def build_cross(cc, d):
    """Build a tiny static ELF with cross-compiler `cc`; return path or None."""
    if not shutil.which(cc):
        return None
    src = os.path.join(d, "t.c")
    with open(src, "w") as f:
        f.write("#include <unistd.h>\nint main(void){write(1,\"x\",1);return 0;}\n")
    out = os.path.join(d, os.path.basename(cc) + ".bin")
    r = subprocess.run([cc, "-static", "-Os", "-o", out, src], capture_output=True, timeout=120)
    return out if r.returncode == 0 and os.path.exists(out) else None


def main():
    fails = []
    upx = shutil.which("upx")
    if not upx:
        print("PASS test_upx_extract (upx tool not installed, skipped)")
        return 0

    with tempfile.TemporaryDirectory() as d:
        # Host-arch base ELF.
        base = shutil.which("true") or shutil.which("cat")
        if base:
            for label, opt in METHODS.items():
                one_pack(upx, base, f"host-{label}", opt, d, fails)
            # Embedded-at-offset case (one method is enough to exercise find_base).
            one_pack(upx, base, "host-embed", [], d, fails, embedded=True)

        # Optional cross-arch coverage (validates ELF32/64 + ARM/ARM64 un-filters).
        ran_cross = []
        for cc, name in [("aarch64-linux-gnu-gcc", "arm64"),
                         ("arm-linux-gnueabi-gcc", "arm"),
                         ("i686-linux-gnu-gcc", "i386")]:
            cbin = build_cross(cc, d)
            if not cbin:
                continue
            ran_cross.append(name)
            for label, opt in METHODS.items():
                one_pack(upx, cbin, f"{name}-{label}", opt, d, fails)

        # -m32 fallback for i386 if no i686 cross-gcc.
        if "i386" not in ran_cross:
            m32 = os.path.join(d, "m32.bin")
            r = subprocess.run(["gcc", "-m32", "-static", "-Os", "-o", m32,
                                os.path.join(d, "t.c") if os.path.exists(os.path.join(d, "t.c"))
                                else base],
                               capture_output=True, timeout=120)
            if r.returncode == 0 and os.path.exists(m32):
                ran_cross.append("i386(-m32)")
                for label, opt in METHODS.items():
                    one_pack(upx, m32, f"i386-{label}", opt, d, fails)

        # Negative: a non-UPX ELF must not yield an unpacked.elf.
        if base:
            got = moria_unpack(base, d)
            check(got is None, "negative: non-UPX ELF produced an unpacked.elf", fails)

    if fails:
        print("FAIL test_upx_extract:")
        for m in fails:
            print("  -", m)
        return 1
    print("PASS test_upx_extract (byte-exact vs upx -d" +
          (f"; cross: {', '.join(ran_cross)}" if ran_cross else "") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
