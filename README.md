# moria

**Find and unpack files in device software**

moria finds files stored inside firmware and other device-software files, including file systems, kernels, startup programs, archives, and keys. It can unpack most of what it finds without administrator access. For each match, it shows the starting byte, file type, and how sure the match is. It can also return structured JSON for scripts and AI tools.

## Why moria

- **Works with many file systems directly, without `sudo`:** SquashFS, ext2/3/4, F2FS, XFS, btrfs, HFS+, NTFS, EROFS, JFFS2, UBIFS, and more.
- **Follows files inside other files.** For example, it can unpack a gzip-compressed SquashFS file found inside a UBI volume, then keep going through what it finds.
- **Gives repeatable results.** The same input produces the same output every time.
- **Handles damaged or malicious input carefully.** It checks every read, keeps writes inside the chosen output folder, and stops compressed data from expanding without limit.
- **Starts with a clear report.** The normal output is an easy-to-read tree. Use JSON (`-j`) when another program needs the results.

## Build and install

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build --prefix ~/.local     # or /usr/local (needs sudo)
```

To build moria, you need `cmake`, a C++20 compiler, and the zlib, liblzma, lz4, and zstd development libraries. Those libraries let `--extract` unpack compressed data. On Debian or Ubuntu, install them with `sudo apt install cmake g++ zlib1g-dev liblzma-dev liblz4-dev libzstd-dev`. If one is unavailable, add `-DMORIA_OPTIONAL_CODECS=ON` to the first build command. The related compression format will then be unavailable, but the rest of moria will still work.

The `moria` program file is **self-contained**: its file-recognition rules are built in, so nothing needs to be installed beside it. For example, `cp build/moria ~/.local/bin` is enough, and a downloaded release can run as-is. To try recognition rules from a folder without rebuilding, pass `--sigs DIR` or set `$MORIA_SIGDIR`.

## Usage

Output is easy to read by default. Pass `-j` for JSON.

```
moria <file>              # show what the file contains and where each match starts
moria <dir>               # check a folder and summarize the important matches
moria -j <file>           # return structured JSON for other programs
moria -e <file>           # unpack to <file>.extracted/ (-C DIR chooses another folder)
moria -c <file>           # copy unchanged byte ranges to <file>.carved/
moria -E <file>           # measure randomness and flag unknown, possibly encrypted areas
moria --list <archive>    # list files inside a tar, cpio, or ZIP file without unpacking
moria --broad <path>      # also use about 2,500 general file-recognition rules
moria --help
```

## Extraction

`-e` unpacks known formats into `<file>.extracted/`. Each match gets its own folder, named `0x<starting-byte>-<type>/`. An index file named `manifest.json` connects each match to its output path. moria automatically opens supported files found inside other files and rebuilds UBI files one volume at a time. The `--depth`, `--max-files`, and `--max-bytes` limits prevent unexpectedly large output. For output larger than 10 MiB, moria also stops any compressed item that expands to more than 1,000 times its input size. When a limit is reached, moria keeps everything it already recovered.

Unpacked directly by moria, with no other programs and no `sudo`:

- **File systems:** SquashFS, ext2/3/4, F2FS, FAT12/16/32, exFAT, NTFS, HFS+/HFSX, XFS, btrfs, JFFS2, UBI/UBIFS, romfs, YAFFS2, cramfs, EROFS
- **Archives and images:** ZIP, tar, cpio, ISO 9660, Android sparse, Android boot
- **Kernels and startup packages:** U-Boot uImage, U-Boot FIT, and separate gzip, xz, zstd, or lz4 compressed files
- **Firmware packages:** RAE Systems / Honeywell RFP, including LZARI-compressed sections

## File-recognition rules

- `signatures/` contains the main, manually maintained rules for firmware file systems, packages, kernels, and common file types. These rules check more than a short byte pattern whenever possible.
- `signatures-firmware/` contains rules for firmware packages from specific vendors. These rules load by default.
- `signatures-generated/` contains about 2,500 general file-type rules based on the `file(1)` recognition database. These rules load only with `--broad`.

To add a format, add a `.toml` file to `signatures/`. A small C++ checker is needed only when the rule must compare separate parts of a file or verify a checksum.

## Scope

moria identifies file contents, unpacks supported formats, and can copy selected byte ranges unchanged. Searching for secrets or passwords, making a software inventory (SBOM), checking for known security problems (CVEs), and reviewing licenses are handled by a separate tool, [mithril](https://github.com/nmatt0/mithril).

## License

See `LICENSE` for moria's MIT license. Licenses for outside code and source data
are listed in `THIRD_PARTY.md`.
