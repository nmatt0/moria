# Outside code and source data

moria itself uses the MIT license (see `LICENSE`). This file lists code and
file-recognition rules that came from, or were based on, other projects. It also
lists their licenses so they can be checked before a public release.

## Code copied into this repository

### third_party/tomlplusplus/toml.hpp
- Original project: https://github.com/marzer/tomlplusplus
- License: **MIT** (`SPDX-License-Identifier: MIT`, Copyright (c) Mark Gillard).
- How moria uses it: reads TOML file-recognition rules. Its MIT license works
  with moria's MIT license. The original copyright notice remains in the copied
  file.

## File-recognition rules based on other projects

The two automatically created rule sets contain **identifying byte patterns**
and short **descriptions**. Only the byte patterns are used to recognize a file.
The descriptions help people understand a match.

### signatures-generated/generated.toml  (loaded only with `--broad`)
- Based on: `file(1)`'s Magdir (https://github.com/file/file), using
  `tools/ingest_magic.py`.
- Source license: **BSD-style** (the "file"/Ian Darwin license — permissive,
  requires the copyright notice be retained on redistribution of source).
- Release note: this rule set may be included when the required credit is also
  included. Keep the `file(1)` copyright notice when sharing the source.

### signatures-firmware/firmware.toml  (loaded by default)
- The byte patterns were checked against the fkie
  **firmware-magic-database** (https://github.com/fkie-cad/firmware-magic-database,
  GPL-3.0).
- Release note: this rule set may be used in moria's MIT-licensed code. The byte
  values and their positions describe real firmware formats. The descriptions
  were rewritten with `tools/reauthor_firmware_desc.py`; they use only the
  vendor or format name, the identifying bytes, and their starting position.
  Wording from the GPL-3.0 source is not included. The `name` values are product
  and format names.
- History: an earlier version included descriptions copied from fkie. They were
  replaced before any release. When rebuilding these rules from an outside
  source, run `reauthor_firmware_desc.py` or an equivalent tool so the new
  descriptions do not copy the source wording.

## Projects reviewed but not copied

No code or byte patterns were copied from binwalk, unblob, EMBA, FACT_core, or
firmware-mod-kit. These projects were reviewed during early design work. moria's
file-checking code is original C++.

## Test files not included in releases

- A private local collection of real vendor firmware is used by
  `tests/accuracy.py`. It is not stored in this repository.
- `tests/samples/` contains made-up example files created by
  `tests/gen_samples.py`. Git ignores this folder, and the files can be created
  again. They do not come from another project.
