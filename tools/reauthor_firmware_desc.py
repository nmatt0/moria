#!/usr/bin/env python3
"""One-shot clean-room re-authoring of signatures-firmware/firmware.toml descriptions.

The firmware magic BYTE PATTERNS and offsets are facts (kept verbatim). The
`name` slugs are factual vendor/format identifiers (kept). Only the human
`description` text is regenerated here, from a uniform template of our own
(display-name + the magic + offset), so no third-party prose survives. Run once;
after this the file is maintained by hand or by re-running with fresh input.

Usage: python3 tools/reauthor_firmware_desc.py   # rewrites the toml in place
"""
import re
import sys

PATH = "signatures-firmware/firmware.toml"

# Display fixups: uppercase real acronyms / correct vendor casing so the
# generated descriptions read as facts, not as slugs. Token -> replacement.
FIX = {
    "tp": "TP", "link": "Link", "vxworks": "VxWorks", "uefi": "UEFI",
    "rtos": "RTOS", "spi": "SPI", "emmc": "eMMC", "nor": "NOR", "cfe": "CFE",
    "ntfs": "NTFS", "luks": "LUKS", "lvm2": "LVM2", "lvm": "LVM", "hp": "HP",
    "dji": "DJI", "avm": "AVM", "ce": "CE", "pv": "PV", "royl": "ROYL",
    "csys": "CSYS", "wrgg": "WRGG", "trx": "TRX", "chk": "CHK", "bneg": "BNEG",
    "shrs": "SHRS", "sao": "SAO", "enck": "ENCK", "pjl": "PJL", "s390": "S390",
    "lilo": "LILO", "roku": "Roku", "qnap": "QNAP", "zyxel": "ZyXEL",
    "lancom": "LANCOM", "ubiquiti": "Ubiquiti", "netgear": "Netgear",
    "broadcom": "Broadcom", "realtek": "Realtek", "mediatek": "MediaTek",
    "xiaomi": "Xiaomi", "xerox": "Xerox", "sercomm": "Sercomm", "senao": "Senao",
    "beyonwiz": "Beyonwiz", "draytek": "Draytek", "instar": "Instar",
    "alphanetworks": "Alphanetworks", "cobalt": "COBALT", "cisco": "Cisco",
    "aculab": "Aculab", "marvell": "Marvell", "libertas": "Libertas",
    "asus": "ASUS", "dell": "Dell", "toshiba": "Toshiba", "seagate": "Seagate",
    "bosch": "Bosch", "digi": "Digi", "frontier": "Frontier", "silicon": "Silicon",
    "ambarella": "Ambarella", "postscript": "PostScript", "minix": "Minix",
    "linux": "Linux", "romfs": "romfs", "squashfs": "SquashFS", "ecos": "eCos",
    "gm8126": "GM8126", "aih0n": "AIH0N", "blcr": "BLCR", "ros": "ROS",
    "img0": "IMG0", "zboot": "ZBOOT", "dlob": "DLOB", "bin": "BIN",
    "dsk1": "DSK1", "cd2": "CD2", "had": "HAD", "mh01": "MH01", "hdr1": "HDR1",
    "hdr2": "HDR2", "sf": "SF", "kdump": "Kdump", "mlocate": "mlocate",
    "xen": "Xen", "sb": "SB", "d": "D", "wwan": "WWAN", "oem": "OEM",
    "voip": "VoIP", "royl": "ROYL", "thompson": "Thompson", "alcatel": "Alcatel",
    "android": "Android", "windows": "Windows", "western": "Western",
    "digital": "Digital", "packimg": "PackImg", "dahua": "Dahua",
    "laserjet": "LaserJet", "pfs": "PFS", "tag": "TAG",
}


def humanize(slug):
    words = [w for w in slug.split("_") if w]
    out = []
    for w in words:
        if w in FIX:
            out.append(FIX[w])
        else:
            out.append(w.capitalize())
    return " ".join(out)


def magic_repr(hexstr):
    b = bytes.fromhex(hexstr)
    if b and all(0x20 <= c <= 0x7e for c in b):
        return '"' + b.decode("ascii") + '"'
    return "0x" + hexstr


def toml_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    text = open(PATH).read()
    # split off the leading comment header, keep the signature blocks
    parts = re.split(r'(?m)^(?=\[\[signature\]\])', text, maxsplit=1)
    if len(parts) != 2:
        sys.exit("could not find first [[signature]] block")
    body = parts[1]
    blocks = re.split(r'(?m)^(?=\[\[signature\]\])', body)

    header = (
        "# Firmware-vendor magic-tier signatures for moria.\n"
        "# Byte patterns and offsets are facts about real firmware formats.\n"
        "# Descriptions are original (name + identifying magic + offset); no\n"
        "# third-party prose is reproduced. See THIRD_PARTY.md for provenance.\n\n"
    )

    out = [header]
    n = 0
    for blk in blocks:
        if not blk.strip():
            continue
        name = re.search(r'name = "([^"]+)"', blk).group(1)
        off = re.search(r'magic_offset = (\d+)', blk)
        off = off.group(1) if off else "0"
        hx = re.search(r'hex = "([0-9a-f]+)"', blk).group(1)
        desc = f"{humanize(name)}; identifying magic {magic_repr(hx)} at offset {off}"
        # Match the whole doc line (greedy .* handles embedded escaped quotes in
        # the original third-party text, e.g. ZyXEL's name: \"%s\").
        blk = re.sub(r'(?m)^doc = \{ description = ".*" \}$',
                     f'doc = {{ description = "{toml_escape(desc)}" }}', blk)
        out.append(blk if blk.endswith("\n") else blk + "\n")
        n += 1

    open(PATH, "w").write("".join(out))
    print(f"re-authored {n} descriptions in {PATH}")


if __name__ == "__main__":
    main()
