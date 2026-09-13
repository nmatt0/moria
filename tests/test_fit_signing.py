#!/usr/bin/env python3
"""FIT verified-boot metadata extraction regression (issue #12, moria side).

`moria -e` on a signed FIT must, besides the /images payloads, write a
fit-signature-info.txt recording the verified-boot structure (per-image hash +
signature algorithms, per-config sign-images + signature, and the /signature
key nodes) and carve each embedded signing key's public material to fit-keys/.
The blob is a dtc-built FIT embedded as base64 (its .its source in the comment);
self-contained, no external tools. Exit nonzero on any failure.
"""
import base64
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

# fit_keyed.its: one signed kernel image (hash-1 sha256 + signature-1
# sha256,rsa2048), a signed conf-1 (sign-images="kernel"), and /signature/
# key-devkey with rsa,n = de ad be ef ca fe ba be 12 34 56 78 9a bc de f0 and
# rsa,e = 00 01 00 01, required="conf".
FIT_KEYED = base64.b64decode(
    "0A3+7QAAA2AAAAA4AAAC4AAAACgAAAARAAAAEAAAAAAAAACAAAACqAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAMA"
    "AAAdAAAAAHNpZ25lZCBGSVQgd2l0aCBlbWJlZGRlZCBrZXkAAAAAAAAAAWltYWdlcwAAAAAAAWtlcm5lbC0xAAAAAAAA"
    "AAMAAAAIAAAADBEiM0RVZneIAAAAAwAAAAcAAAARa2VybmVsAAAAAAADAAAABgAAABZhcm02NAAAAAAAAAMAAAAGAAAA"
    "G2xpbnV4AAAAAAAAAwAAAAUAAAAebm9uZQAAAAAAAAABaGFzaC0xAAAAAAADAAAABwAAACpzaGEyNTYAAAAAAAMAAAAI"
    "AAAALwAAAKoAAAC7AAAAAgAAAAFzaWduYXR1cmUtMQAAAAADAAAADwAAACpzaGEyNTYscnNhMjA0OAAAAAAAAwAAAAcA"
    "AAA1ZGV2a2V5AAAAAAADAAAACAAAAC8AAADMAAAA3QAAAAIAAAACAAAAAgAAAAFjb25maWd1cmF0aW9ucwAAAAAAAwAA"
    "AAcAAABDY29uZi0xAAAAAAABY29uZi0xAAAAAAADAAAACQAAAEtrZXJuZWwtMQAAAAAAAAABc2lnbmF0dXJlLTEAAAAA"
    "AwAAAA8AAAAqc2hhMjU2LHJzYTIwNDgAAAAAAAMAAAAHAAAANWRldmtleQAAAAAAAwAAAAcAAABSa2VybmVsAAAAAAAC"
    "AAAAAgAAAAIAAAABc2lnbmF0dXJlAAAAAAAAAWtleS1kZXZrZXkAAAAAAAMAAAAPAAAAKnNoYTI1Nixyc2EyMDQ4AAAA"
    "AAADAAAABwAAADVkZXZrZXkAAAAAAAMAAAAEAAAAXgAACAAAAAADAAAAEAAAAGverb7vyv66vhI0VniavN7wAAAAAwAA"
    "AAQAAABxAAEAAQAAAAMAAAAFAAAAd2NvbmYAAAAAAAAAAgAAAAIAAAACAAAACWRlc2NyaXB0aW9uAGRhdGEAdHlwZQBh"
    "cmNoAG9zAGNvbXByZXNzaW9uAGFsZ28AdmFsdWUAa2V5LW5hbWUtaGludABkZWZhdWx0AGtlcm5lbABzaWduLWltYWdl"
    "cwByc2EsbnVtLWJpdHMAcnNhLG4AcnNhLGUAcmVxdWlyZWQA")


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as td:
        img = os.path.join(td, "fit_keyed.itb")
        with open(img, "wb") as f:
            f.write(FIT_KEYED)
        outdir = os.path.join(td, "out")
        subprocess.run([MORIA, "-e", "-C", outdir, img], capture_output=True, text=True)
        sub = None
        for d in os.listdir(outdir):
            if os.path.isdir(os.path.join(outdir, d)):
                sub = os.path.join(outdir, d)
        check(sub is not None, "fit extracted to a subdir")
        if not sub:
            print("\nFAIL")
            return 1

        info_p = os.path.join(sub, "fit-signature-info.txt")
        check(os.path.isfile(info_p), "fit-signature-info.txt written")
        info = open(info_p).read() if os.path.isfile(info_p) else ""
        check("signature=sha256,rsa2048" in info, "records image signature algorithm")
        check("sign-images=kernel" in info, "records config sign-images")
        check("key-devkey" in info and "rsa-bits=2048" in info and "required=conf" in info,
              "records signing key (hint, rsa-bits, required)")

        key_p = os.path.join(sub, "fit-keys", "key-devkey.bin")
        check(os.path.isfile(key_p), "embedded signing key carved to fit-keys/")
        if os.path.isfile(key_p):
            kb = open(key_p, "rb").read()
            check(kb == bytes.fromhex("deadbeefcafebabe123456789abcdef000010001"),
                  "carved key = rsa,n || rsa,e byte-for-byte")

        # A payload was still extracted (the kernel image).
        check(os.path.isfile(os.path.join(sub, "kernel-1")), "kernel payload still extracted")

    if fails:
        print(f"\nFAIL: {len(fails)} check(s) failed")
        return 1
    print("\nPASS: FIT verified-boot metadata + key carve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
