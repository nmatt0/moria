# moria

**IoT firmware identification and extraction**

moria identifies files and the structures embedded inside firmware and IoT images (filesystems, kernels, bootloaders, archives, keys) and unpacks most of what it finds, without root. It reports each finding with a byte offset, a type, and a confidence score, and it speaks clean JSON so scripts and LLM agents can drive it as easily as people can.

## Why moria

- **Extracts a broad set of filesystems in-process, without sudo:** SquashFS, ext2/3/4, F2FS, XFS, btrfs, HFS+, NTFS, EROFS, JFFS2, UBIFS, and more.
- **Recursive by default.** A gzip-wrapped SquashFS inside a UBI volume unpacks all the way down.
- **Deterministic.** The same input always produces the same output; conflict resolution has no random tie-break.
- **Safe on hostile input.** Every read is bounds-checked, every write goes through `openat` + `O_NOFOLLOW` (no path-traversal or symlink escape), and decompression is bounded against bombs.
- **Identification-first.** A readable tree by default, JSON (`-j`) for tools, with offsets and confidence on every finding.

## Build & Install

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build --prefix ~/.local     # or /usr/local (needs sudo)
```

Build needs `cmake`, a C++20 compiler, and the zlib, liblzma, lz4, and zstd development libraries (the decompressors used by `--extract`). On Debian/Ubuntu: `sudo apt install cmake g++ zlib1g-dev liblzma-dev liblz4-dev libzstd-dev`. To build without one (a minimal or identify-only build), configure with `-DMORIA_OPTIONAL_CODECS=ON` and the missing codec is simply disabled.

The `moria` binary is **self-contained**: all signature sets are embedded at build time, so the binary works anywhere with nothing installed alongside it (`cp build/moria ~/.local/bin` is enough, and a downloaded release binary just runs). To use external signatures instead of the embedded ones (to test a new `.toml` without rebuilding, say), pass `--sigs DIR` or set `$MORIA_SIGDIR`.

## Usage

Output is human-readable by default. Pass `-j` for JSON.

```
moria <file>              # identify: a findings tree with offsets, types, and confidence
moria <dir>               # scan a tree: a type summary plus the notable files
moria -j <file>           # JSON, for tools and agents
moria -e <file>           # extract to <file>.extracted/   (-C DIR to choose the output dir)
moria -c <file>           # carve raw byte ranges to <file>.carved/ (no parsing)
moria -E <file>           # entropy pass: flag unidentified / possibly-encrypted regions
moria --list <archive>    # list tar/cpio/zip members without extracting
moria --broad <path>      # also load the ~2.5k general file-type signatures
moria --help
```

## Extraction

`-e` unpacks recognized formats under `<file>.extracted/`, one directory per region (`0x<offset>-<type>/`), plus a `manifest.json` mapping offsets to paths. It recurses into nested containers automatically and rebuilds UBI images volume by volume. Guards (`--depth`, `--max-files`, `--max-bytes`, and a decompression-ratio cap) bound hostile input; a tripped guard stops that branch and still returns everything recovered.

Unpacked in-process, no external tools and no sudo:

- **Filesystems:** SquashFS, ext2/3/4, F2FS, FAT12/16/32, exFAT, NTFS, HFS+/HFSX, XFS, btrfs, JFFS2, UBI/UBIFS, romfs, YAFFS2, cramfs, EROFS
- **Archives and images:** ZIP, tar, cpio, ISO 9660, Android sparse, Android boot
- **Kernels and wrappers:** U-Boot uImage, U-Boot FIT, standalone gzip / xz / zstd / lz4 streams

## Signatures

- `signatures/` is the hand-written core: firmware filesystems, containers, kernels, and common formats, each with structural validation.
- `signatures-firmware/` holds vendor firmware-container magics and loads by default.
- `signatures-generated/` holds ~2.5k general file-type magics derived from `file(1)`'s magic database and loads only with `--broad`.

To add a format, drop a `.toml` in `signatures/`. A small C++ validator is only needed for checks the declarative layer can't express, such as CRCs or cross-block pointers.

## Scope

moria does structural identification, extraction, and carving. Secret/credential scanning, SBOM, CVE, and license analysis are a separate tool ([mithril](https://github.com/nmatt0/mithril)).

## License

MIT, see `LICENSE`. Third-party code and derived-data licenses are listed in `THIRD_PARTY.md`.
