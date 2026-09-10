#!/usr/bin/env bash
# Rebuild the two imported file-recognition rule sets. Requires local copies of
# repos/file and repos/firmware-magic-database (see ../repos).
#   - signatures-generated/generated.toml : general file types from file(1)'s
#     Magdir (loaded only with --broad).
#   - signatures-firmware/firmware.toml   : firmware vendor formats from the fkie
#     firmware-magic-database (clear text patterns only; loaded by default).
set -euo pipefail
cd "$(dirname "$0")/.."
REPOS=../repos
FILE_MAGDIR="$REPOS/file/magic/Magdir"
FMD="$REPOS/firmware-magic-database/mime"

# General rules used only with --broad.
python3 tools/ingest_magic.py --out signatures-generated/generated.toml "$FILE_MAGDIR"

# Firmware rules: import clear text patterns from the firmware sections of the
# fkie database. Skip broad guesses that cause too many wrong matches.
python3 tools/ingest_magic.py --out signatures-firmware/firmware.toml \
  --strings-only --min-len 4 \
  "$FMD/firmware_containers" "$FMD/bootloader" "$FMD/file_systems" \
  "$FMD/uefi" "$FMD/printer" "$FMD/drone" "$FMD/linux"
