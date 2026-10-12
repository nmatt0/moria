# Writing moria signatures

How `.toml` signatures work: what each field means, what the engine does with
it, and the semantics that aren't obvious from the grammar alone. File-by-file
examples live in `signatures/`; this document explains the rules those files
follow.

## Loading

Drop a `.toml` into `signatures/` (or point `--sigs DIR` / `$MORIA_SIGDIR` at a
directory). Files are embedded into the binary at build time; `--sigs` replaces
the embedded set for the run, which is how you test a new signature without
rebuilding.

A file that fails to load (bad hex, unknown field name in an expression, no
`[[magic]]`) is **skipped with a diagnostic** — it never takes the process
down. Check stderr when a new signature doesn't seem to fire.

## Magic

```toml
[[magic]]
hex = "27051956"      # or: ascii = "hsqs"
endian = "big"
```

- `hex` must be even-length; `ascii` is a convenience for text magics.
- `endian` is **how the magic bytes appear in the file** — it is not a claim
  about the format's internal field order. `"big"` or `"be"`; anything else is
  little-endian.
- One signature may list several `[[magic]]` blocks, including the same bytes
  under different endiannesses. The validator runs once per match, and the
  endianness of the *matched* magic is used to decode the `struct` and is
  recorded on the finding (see [Endianness](#endianness)).

## `magic_offset` — where the structure starts

The engine locates the **magic**, but signatures describe a **structure**.
`magic_offset` is the distance from the structure's first byte to the magic
bytes:

```
structure_start = match_position - magic_offset
```

- A match whose structure would start before byte 0 of the file is rejected.
- The validator's `ctx.offset` is the **structure start**, not the magic
  position. Every code comment of the form "magic_offset already subtracted"
  refers to this.
- Default is `0` — the magic *is* the first byte of the structure. That is the
  case for most formats, including ones where the anchor is a *field* of the
  structure rather than a traditional magic: `jzlzma-raw` anchors on the
  dictionary-size power-of-two field, which is struct field 0, so
  `magic_offset = 0` even though nothing about it looks like a classic magic.
- The classic non-zero case is a magic that sits *inside* a superblock:
  `littlefs` matches `0x25395230` ("tinyfs"-family counter magic) at offset 8,
  declares `magic_offset = 8`, and its validator receives `ctx.offset` pointing
  at the superblock start so it can read the rev-count pairs around it.

## `short` — start-of-file-only signatures

`short = true` restricts the signature to matches whose structure starts at
byte 0 of the scanned file (the engine drops any match position other than
`magic_offset` itself). Use it for formats that are meaningless mid-file
(BMP, IHEX, HFS+ partition images) to keep them from firing on lookalike
bytes inside other data. Never set `short` on embeddable formats — a yaffs2 or
jzlzma stream legitimately lives mid-stream.

## `struct`, `constraints`, `size`

```toml
struct = """
  u32 ih_magic;
  u32 ih_hcrc;
  ...
  bytes[32] ih_name;
"""
constraints = [ "ih_size + 64 <= _avail" ]
size = "ih_size + 64"
```

- Fields: `u8`, `u16`, `u32`, `bytes[N]`, decoded per the matched magic's
  endianness. Field names become variables for `constraints`, `size`, and the
  validator's `FieldMap`.
- Available pseudo-variables: `_avail` (bytes from structure start to end of
  scanned data) and `_offset`.
- **`constraints` are identity checks**: every one must pass or the candidate
  is discarded entirely. Expressions are validated at load time — an unknown
  variable name rejects the signature file.
- **`soft_constraints` are validity checks**: failing one doesn't reject the
  candidate, it downgrades the finding to the `magic` tier with `soft_evidence`
  as the reason. Use them for "a real one never looks like this, but the bytes
  alone can't prove it".
- `size` is an expression evaluating to the structure's size; the engine uses
  it to own the byte range. A validator that distrusts the declared size
  (e.g. `uimage` on header-CRC failure) sets the size to 0 so a bogus length
  can't mask unrelated data behind it.
- `size_clamp = true` lets a declared size larger than the remaining data be
  clamped instead of dropped; `coalesce = true` merges adjacent same-type
  matches (see `src/signature.hpp` for the precise behaviour).

## Endianness

Two different things are called "endian" and they are **not** the same:

1. **Signature endianness** (`[[magic]].endian`): how the magic — and
   therefore the `struct` — is laid out *in the file*. This is a fact about
   the byte stream. When writing a magic, check the bytes on disk, not what
   the format documentation calls itself; container headers are routinely
   little-endian even for big-endian targets (Ingenic's `mark_rootfs_lzma`
   wrapper is LE on BE MIPS devices).

2. **`Finding.endian`**: copied from the *matched magic's* endianness. It is
   surfaced as `little`/`big` in JSON output and in the human NOTES column
   (rendered as e.g. `big/mips`). It says "this structure's header is
   big-endian" — nothing more.

**The trap:** for container formats whose *payload* byte order differs from
their header, `Finding.endian` will be read by users as a payload claim if you
stay silent. The `uImage` case is canonical: the 64-byte header is always
big-endian, but the format does not record the payload's byte order
(`ih_arch` names a CPU family, not an endianness), and mipsel kernels inside
big-endian-headered uImages are common on Ingenic hardware. The `uimage`
validator therefore always attaches an `info` diagnostic
(`uimage-payload-endian-unknown`). If your format has the same property, do
the same — a one-line diagnostic is cheaper than a wrong reverse-engineering
session.

## Validators

A validator turns "bytes that look like X" into "X, verified" — or rejects the
candidate by returning `false`.

- Register it in `src/validators/registry.cpp` under the name your TOML's
  `validator = "..."` references.
- You get: the `Reader`, `ctx.offset` (structure start), the endian-decoded
  `FieldMap`, and `ctx.out` (the `Finding`).
- Set confidence deliberately: `set_confidence(Confidence::Verified, "reason")`
  after a real check (CRC, trial decode); leave structural otherwise. Tiers:
  `magic` < `structural` < `consistent` < `verified`.
- Attach caveats as diagnostics: `{severity, code, message}` with `severity`
  one of `error` (moria could not do something it normally does), `warning`
  (reduced confidence or a caveat), `info` (neutral note). Codes are stable
  machine slugs (`jzlzma-short`, `uimage-payload-endian-unknown`) — they show
  up in scripts, so don't rename them casually.
- Expensive validation is fine if it's *decisive*: trial-decoding a compressed
  stream (the jzlzma validators) gives a near-zero false-positive rate that no
  static check can match.

## Adding a format, end to end

1. `signatures/<name>.toml` — magic(s), struct, constraints, size, `[doc]`
   (description + references), and a `validator` only if the declarative layer
   can't express the check (CRCs, cross-block pointers, trial decodes).
2. Validator `.cpp/.hpp` in `src/validators/` + registry entry + CMakeLists.
3. An extractor in `src/extract/` if the format should unpack (`-e`, `--list`).
4. A synthetic fixture in `tests/gen_samples.py` (append to `MANIFEST`) — the
   coverage gate in `tests/test_samples.py` fails the suite for core
   signatures without one.
5. A regression test in `tests/` for anything the fixture can't pin down
   (false-positive guards, ownership splits between sibling signatures).
