#!/usr/bin/env bash
# Regenerate the two ingested signature sets. Needs repos/file and
# repos/firmware-magic-database cloned (see ../repos).
#   - signatures-generated/generated.toml : general file types from file(1)'s
#     Magdir (loaded only with --broad).
#   - signatures-firmware/firmware.toml   : firmware vendor formats from the fkie
#     firmware-magic-database (strings-only, distinctive; loaded by default).
set -euo pipefail
cd "$(dirname "$0")/.."
REPOS=../repos
FILE_MAGDIR="$REPOS/file/magic/Magdir"
FMD="$REPOS/firmware-magic-database/mime"

# General set (broad breadth, magic tier, --broad only)
python3 tools/ingest_magic.py --out signatures-generated/generated.toml "$FILE_MAGDIR"

# Firmware set (curated: distinctive string magics from firmware-focused fkie
# categories; skip the noisy raw-stream heuristics in lzma/raw/encoding).
python3 tools/ingest_magic.py --out signatures-firmware/firmware.toml \
  --strings-only --min-len 4 \
  "$FMD/firmware_containers" "$FMD/bootloader" "$FMD/file_systems" \
  "$FMD/uefi" "$FMD/printer" "$FMD/drone" "$FMD/linux"
