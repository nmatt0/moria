// lzx.cpp — LZX bitstream decoder plus the CE-ROM and MS-CAB framings.
// See lzx.hpp for what each entry point expects.
//
// The bitstream layer follows the published LZX description: 16-bit
// little-endian refills into a 32-bit buffer, MSB-first consumption, a pretree
// coding the main/length tree code lengths as deltas mod 17, three repeated
// match offsets (R0/R1/R2), and an optional x86 CALL (0xE8) translation pass
// over the decoded bytes. Written against moria's own bounds-checked buffers.
#include "extract/lzx.hpp"

#include <algorithm>
#include <cstring>

namespace ft {

namespace {

constexpr unsigned kNumChars = 256;
constexpr unsigned kNumPrimaryLengths = 7;
constexpr unsigned kMinMatch = 2;
constexpr unsigned kMaxMatch = 257;

constexpr unsigned kPretreeElems = 20;
constexpr unsigned kSecondaryElems = 249;
constexpr unsigned kAlignedElems = 8;

constexpr unsigned kPretreeMaxSymbols = kPretreeElems;
constexpr unsigned kPretreeTableBits = 6;
constexpr unsigned kMaintreeMaxSymbols = kNumChars + (51u << 3);
constexpr unsigned kMaintreeTableBits = 11;
constexpr unsigned kLentreeMaxSymbols = kSecondaryElems;
constexpr unsigned kLentreeTableBits = 10;
constexpr unsigned kAligntreeMaxSymbols = kAlignedElems;
constexpr unsigned kAligntreeTableBits = 7;

// read_lengths() can run past `last` by one repeat (max 51 entries), so every
// length table carries this much slack past its symbol count.
constexpr unsigned kLenTableSafety = 64;

constexpr unsigned kBlockVerbatim = 1;
constexpr unsigned kBlockAligned = 2;
constexpr unsigned kBlockUncompressed = 3;

constexpr size_t kCabFrameSize = 32768;

// Number of position slots per window size (15..21 bits).
constexpr unsigned kPositionSlots[7] = {30, 32, 34, 36, 38, 42, 50};

constexpr uint8_t kExtraBits[51] = {
    0,  0,  0,  0,  1,  1,  2,  2,  3,  3,  4,  4,  5,  5,  6,  6,  7,
    7,  8,  8,  9,  9,  10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15,
    16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17};

constexpr uint32_t kPositionBase[51] = {
    0,       1,       2,       3,       4,       6,       8,       12,      16,      24,
    32,      48,      64,      96,      128,     192,     256,     384,     512,     768,
    1024,    1536,    2048,    3072,    4096,    6144,    8192,    12288,   16384,   24576,
    32768,   49152,   65536,   98304,   131072,  196608,  262144,  393216,  524288,  655360,
    786432,  917504,  1048576, 1179648, 1310720, 1441792, 1572864, 1703936, 1835008, 1966080,
    2097152};

// MSB-first bit reader over a byte span, refilled 16 bits at a time in
// little-endian word order. Reads past the end yield zero bits and latch
// `overrun`, so a truncated stream fails cleanly instead of reading OOB.
class BitReader {
public:
    explicit BitReader(std::span<const uint8_t> in) : in_(in) {}

    // n must be <= 17: the buffer holds 32 bits and refills in 16-bit units, so
    // a larger request could need three injections and shift negatively. The
    // two wider fields in LZX (the 24-bit block length and the 32-bit file size)
    // are read as two calls by the caller.
    uint32_t read(unsigned n) {
        if (n == 0) return 0;
        ensure(n);
        uint32_t v = peek(n);
        remove(n);
        return v;
    }

    void ensure(unsigned n) {
        while (left_ < static_cast<int>(n)) {
            uint32_t lo = byte_();
            uint32_t hi = byte_();
            buf_ |= ((hi << 8) | lo) << (32 - 16 - left_);
            left_ += 16;
        }
    }

    uint32_t peek(unsigned n) const { return buf_ >> (32 - n); }
    void remove(unsigned n) {
        buf_ <<= n;
        left_ -= static_cast<int>(n);
    }
    uint32_t raw() const { return buf_; }
    int left() const { return left_; }

    // Drop the partially-consumed word and realign to the byte stream. Used
    // around an uncompressed block, whose payload is read as plain bytes.
    void align() {
        buf_ = 0;
        left_ = 0;
    }

    // Discard the bits left in the current 16-bit word. CAB pads the bitstream
    // to a word boundary at the end of every 32 KiB output frame, so the next
    // frame starts on one; without this the reader stays half a word ahead for
    // the rest of the stream.
    void align_word() {
        if (left_ > 0) ensure(16);
        if (left_ & 15) remove(static_cast<unsigned>(left_ & 15));
    }

    size_t pos() const { return pos_; }
    void set_pos(size_t p) { pos_ = p; }
    size_t size() const { return in_.size(); }
    // The 16-bit lookahead legitimately reads a few bytes past the last symbol
    // of a well-formed stream; anything beyond that is a truncated stream.
    bool overrun_past(size_t slack) const { return pos_ > in_.size() + slack; }

    // Read `n` plain bytes at the current position (used for uncompressed
    // blocks and the stored R0/R1/R2 triple). False if the stream is short.
    bool take_bytes(uint8_t* dst, size_t n) {
        if (n > in_.size() - std::min(pos_, in_.size())) {
            overrun_ = true;
            return false;
        }
        std::memcpy(dst, in_.data() + pos_, n);
        pos_ += n;
        return true;
    }

private:
    uint32_t byte_() {
        if (pos_ >= in_.size()) {
            overrun_ = true;
            ++pos_;
            return 0;
        }
        return in_[pos_++];
    }

    std::span<const uint8_t> in_;
    size_t pos_ = 0;
    uint32_t buf_ = 0;
    int left_ = 0;
    bool overrun_ = false;
};

// Build the two-level Huffman decode table used by LZX: a direct-indexed table
// for codes up to `nbits` long, with longer codes walking a binary tree grafted
// past the direct region. Layout matches the reference decoder so the same
// length arrays drive it.
bool make_decode_table(unsigned nsyms, unsigned nbits, const uint8_t* length,
                       std::vector<uint16_t>& table) {
    const size_t tsize = (size_t(1) << nbits) + (size_t(nsyms) << 1);
    if (table.size() != tsize) table.assign(tsize, 0);
    else std::fill(table.begin(), table.end(), 0);

    uint32_t table_mask = 1u << nbits;
    uint32_t bit_mask = table_mask >> 1;
    uint32_t pos = 0;
    uint32_t next_symbol = bit_mask;

    unsigned bit_num = 1;
    for (; bit_num <= nbits; ++bit_num, bit_mask >>= 1) {
        for (unsigned sym = 0; sym < nsyms; ++sym) {
            if (length[sym] != bit_num) continue;
            uint32_t leaf = pos;
            pos += bit_mask;
            if (pos > table_mask) return false;  // codes overflow the table
            for (uint32_t k = 0; k < bit_mask; ++k) table[leaf++] = static_cast<uint16_t>(sym);
        }
    }

    if (pos != table_mask) {
        for (uint32_t sym = pos; sym < table_mask; ++sym) table[sym] = 0;

        // Codes longer than nbits: extend into the tree area past the table.
        uint64_t pos_hi = uint64_t(pos) << 16;
        uint64_t mask_hi = uint64_t(table_mask) << 16;
        bit_mask = 1u << 15;

        for (; bit_num <= 16; ++bit_num, bit_mask >>= 1) {
            for (unsigned sym = 0; sym < nsyms; ++sym) {
                if (length[sym] != bit_num) continue;
                uint32_t leaf = static_cast<uint32_t>(pos_hi >> 16);
                for (unsigned fill = 0; fill < bit_num - nbits; ++fill) {
                    if (leaf >= table.size()) return false;
                    if (table[leaf] == 0) {
                        const size_t lo = size_t(next_symbol) << 1;
                        if (lo + 1 >= table.size()) return false;
                        table[lo] = 0;
                        table[lo + 1] = 0;
                        table[leaf] = static_cast<uint16_t>(next_symbol++);
                    }
                    leaf = uint32_t(table[leaf]) << 1;
                    if ((pos_hi >> (15 - fill)) & 1) leaf++;
                }
                if (leaf >= table.size()) return false;
                table[leaf] = static_cast<uint16_t>(sym);
                pos_hi += bit_mask;
                if (pos_hi > mask_hi) return false;
            }
        }
        if (pos_hi != mask_hi) {
            // An incomplete code is legal only when no symbol is used at all.
            for (unsigned sym = 0; sym < nsyms; ++sym)
                if (length[sym] != 0) return false;
        }
        return true;
    }
    return true;
}

// One LZX stream. `out` grows linearly; matches resolve against it directly.
class LzxDecoder {
public:
    LzxDecoder(std::span<const uint8_t> in, unsigned window_bits, size_t cap)
        : bits_(in), cap_(cap) {
        window_bits_ = window_bits;
        main_elements_ = kNumChars + (kPositionSlots[window_bits - 15] << 3);
        out.reserve(std::min<size_t>(cap, size_t(1) << 20));
    }

    static bool window_ok(unsigned window_bits) { return window_bits >= 15 && window_bits <= 21; }

    // Read the one-time stream header (the optional x86 translation size).
    bool read_header() {
        if (bits_.read(1) == 1) {
            uint32_t hi = bits_.read(16);
            uint32_t lo = bits_.read(16);
            intel_filesize_ = static_cast<int32_t>((hi << 16) | lo);
        }
        return true;
    }

    // Decode until `out` holds at least `target` bytes.
    bool decode_until(size_t target) {
        while (out.size() < target) {
            if (block_remaining_ == 0 && !start_block()) return false;
            const size_t want = target - out.size();
            const size_t run = std::min<size_t>(block_remaining_, want);
            const size_t before = out.size();
            if (block_type_ == kBlockUncompressed) {
                if (!copy_stored(run)) return false;
            } else {
                if (!decode_block(run)) return false;
            }
            const size_t produced = out.size() - before;
            // A final match may overrun the requested run, but never its block.
            if (produced == 0 || produced > block_remaining_) return false;
            block_remaining_ -= static_cast<uint32_t>(produced);
            if (out.size() > cap_) return false;
            if (bits_.overrun_past(8)) return false;
        }
        return true;
    }

    bool intel_started() const { return intel_started_; }
    int32_t intel_filesize() const { return intel_filesize_; }

    // Consume the pad bits that end a CAB output frame. Not used by the CE ROM
    // framing, whose blocks are each a self-contained stream.
    void align_frame() { bits_.align_word(); }

    std::vector<uint8_t> out;

private:
    bool start_block() {
        if (block_type_ == kBlockUncompressed) {
            if (block_length_ & 1) bits_.set_pos(bits_.pos() + 1);  // odd-length pad byte
            block_type_ = 0;
            bits_.align();
        }
        block_type_ = bits_.read(3);
        const uint32_t hi = bits_.read(16);
        const uint32_t lo = bits_.read(8);
        block_length_ = (hi << 8) | lo;
        block_remaining_ = block_length_;
        if (block_length_ == 0) return false;  // would not make progress

        if (block_type_ == kBlockAligned) {
            for (unsigned i = 0; i < kAlignedElems; ++i)
                aligntree_len_[i] = static_cast<uint8_t>(bits_.read(3));
            if (!make_decode_table(kAligntreeMaxSymbols, kAligntreeTableBits, aligntree_len_,
                                   aligntree_tab_))
                return false;
        }

        if (block_type_ == kBlockVerbatim || block_type_ == kBlockAligned) {
            if (!read_lengths(maintree_len_, 0, kNumChars)) return false;
            if (!read_lengths(maintree_len_, kNumChars, main_elements_)) return false;
            if (!make_decode_table(kMaintreeMaxSymbols, kMaintreeTableBits, maintree_len_,
                                   maintree_tab_))
                return false;
            if (maintree_len_[0xE8] != 0) intel_started_ = true;
            if (!read_lengths(lentree_len_, 0, kSecondaryElems)) return false;
            if (!make_decode_table(kLentreeMaxSymbols, kLentreeTableBits, lentree_len_,
                                   lentree_tab_))
                return false;
            return true;
        }
        if (block_type_ == kBlockUncompressed) {
            intel_started_ = true;
            // Realign to a byte boundary, then read the stored R0/R1/R2.
            bits_.ensure(16);
            if (bits_.left() > 16) bits_.set_pos(bits_.pos() - 2);
            bits_.align();
            uint8_t r[12];
            if (!bits_.take_bytes(r, sizeof(r))) return false;
            R0_ = le32(r);
            R1_ = le32(r + 4);
            R2_ = le32(r + 8);
            return true;
        }
        return false;  // invalid block type
    }

    static uint32_t le32(const uint8_t* p) {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
               (uint32_t(p[3]) << 24);
    }

    bool copy_stored(size_t n) {
        if (out.size() + n > cap_) return false;
        const size_t at = out.size();
        out.resize(at + n);
        return bits_.take_bytes(out.data() + at, n);
    }

    // Read a Huffman symbol: index the direct table, then walk the grafted tree
    // for codes longer than the table's bit width.
    bool read_sym(const std::vector<uint16_t>& tab, const uint8_t* lens, unsigned nsyms,
                  unsigned nbits, unsigned max_codeword, unsigned& sym_out) {
        if (tab.size() < (size_t(1) << nbits)) return false;
        bits_.ensure(max_codeword);
        uint32_t i = tab[bits_.peek(nbits)];
        if (i >= nsyms) {
            uint32_t j = 1u << (32 - nbits);
            for (;;) {
                j >>= 1;
                if (j == 0) return false;
                i <<= 1;
                i |= (bits_.raw() & j) ? 1u : 0u;
                if (i >= tab.size()) return false;
                i = tab[i];
                if (i < nsyms) break;
            }
        }
        if (lens[i] == 0) return false;  // unused symbol: the stream is corrupt
        bits_.remove(lens[i]);
        sym_out = i;
        return true;
    }

    // Decode the pretree, then the run-length-coded length deltas it describes.
    bool read_lengths(uint8_t* lens, unsigned first, unsigned last) {
        for (unsigned x = 0; x < kPretreeElems; ++x)
            pretree_len_[x] = static_cast<uint8_t>(bits_.read(4));
        if (!make_decode_table(kPretreeMaxSymbols, kPretreeTableBits, pretree_len_, pretree_tab_))
            return false;

        unsigned x = first;
        while (x < last) {
            unsigned z = 0;
            if (!read_sym(pretree_tab_, pretree_len_, kPretreeMaxSymbols, kPretreeTableBits, 16, z))
                return false;
            if (z == 17) {
                unsigned y = bits_.read(4) + 4;
                while (y--) lens[x++] = 0;
            } else if (z == 18) {
                unsigned y = bits_.read(5) + 20;
                while (y--) lens[x++] = 0;
            } else if (z == 19) {
                unsigned y = bits_.read(1) + 4;
                unsigned z2 = 0;
                if (!read_sym(pretree_tab_, pretree_len_, kPretreeMaxSymbols, kPretreeTableBits, 16,
                              z2))
                    return false;
                const uint8_t v = static_cast<uint8_t>((lens[x] + 17 - z2) % 17);
                while (y--) lens[x++] = v;
            } else {
                lens[x] = static_cast<uint8_t>((lens[x] + 17 - z) % 17);
                x++;
            }
        }
        return true;
    }

    // Decode at least `run` bytes of a verbatim/aligned block; a trailing match
    // may produce a little more (the caller accounts for it).
    bool decode_block(size_t run) {
        const size_t stop = out.size() + run;
        while (out.size() < stop) {
            unsigned main_element = 0;
            if (!read_sym(maintree_tab_, maintree_len_, kMaintreeMaxSymbols, kMaintreeTableBits, 16,
                          main_element))
                return false;
            if (main_element < kNumChars) {
                if (out.size() >= cap_) return false;
                out.push_back(static_cast<uint8_t>(main_element));
                continue;
            }

            main_element -= kNumChars;
            size_t match_length = main_element & kNumPrimaryLengths;
            if (match_length == kNumPrimaryLengths) {
                unsigned footer = 0;
                if (!read_sym(lentree_tab_, lentree_len_, kLentreeMaxSymbols, kLentreeTableBits, 16,
                              footer))
                    return false;
                match_length += footer;
            }
            match_length += kMinMatch;
            if (match_length > kMaxMatch) return false;

            uint32_t slot = main_element >> 3;
            uint32_t match_offset;
            if (slot > 2) {
                if (slot >= 51) return false;
                const unsigned extra = kExtraBits[slot];
                uint32_t verbatim_bits, aligned_bits = 0;
                // The LZX description says an aligned symbol is read when the
                // extra-bit count exceeds 3; it is actually read when it is 3
                // or more.
                if (block_type_ == kBlockAligned && extra >= 3) {
                    verbatim_bits = bits_.read(extra - 3) << 3;
                    unsigned a = 0;
                    if (!read_sym(aligntree_tab_, aligntree_len_, kAligntreeMaxSymbols,
                                  kAligntreeTableBits, 8, a))
                        return false;
                    aligned_bits = a;
                } else {
                    verbatim_bits = bits_.read(extra);
                }
                match_offset = kPositionBase[slot] + verbatim_bits + aligned_bits - 2;
                R2_ = R1_;
                R1_ = R0_;
                R0_ = match_offset;
            } else if (slot == 0) {
                match_offset = R0_;
            } else if (slot == 1) {
                match_offset = R1_;
                R1_ = R0_;
                R0_ = match_offset;
            } else {
                match_offset = R2_;
                R2_ = R0_;
                R0_ = match_offset;
            }

            if (match_offset == 0 || match_offset > (1u << window_bits_)) return false;
            if (out.size() + match_length > cap_) return false;
            if (!emit_match(match_offset, match_length)) return false;
        }
        return true;
    }

    // Copy a match. A reference reaching before the start of the stream lands in
    // the never-written part of the LZX window, which the format initializes to
    // 0xDC; reproduce that rather than reading out of bounds.
    bool emit_match(uint32_t offset, size_t len) {
        size_t pos = out.size();
        if (offset > pos) {
            const size_t pre = std::min<size_t>(offset - pos, len);
            out.insert(out.end(), pre, 0xDC);
            len -= pre;
            if (len == 0) return true;
            pos = 0;  // the wrapped copy resumes at the start of the stream
        } else {
            pos -= offset;
        }
        for (size_t k = 0; k < len; ++k) {
            if (pos >= out.size()) return false;
            out.push_back(out[pos++]);
        }
        return true;
    }

    BitReader bits_;
    size_t cap_;
    unsigned window_bits_ = 15;
    unsigned main_elements_ = kNumChars;

    uint32_t R0_ = 1, R1_ = 1, R2_ = 1;
    unsigned block_type_ = 0;
    uint32_t block_length_ = 0;
    uint32_t block_remaining_ = 0;
    bool intel_started_ = false;
    int32_t intel_filesize_ = 0;

    uint8_t pretree_len_[kPretreeMaxSymbols + kLenTableSafety] = {};
    uint8_t maintree_len_[kMaintreeMaxSymbols + kLenTableSafety] = {};
    uint8_t lentree_len_[kLentreeMaxSymbols + kLenTableSafety] = {};
    uint8_t aligntree_len_[kAligntreeMaxSymbols + kLenTableSafety] = {};
    std::vector<uint16_t> pretree_tab_, maintree_tab_, lentree_tab_, aligntree_tab_;
};

// Undo the encoder's x86 CALL translation over one frame of decoded bytes:
// absolute targets within [-curpos, filesize) go back to relative.
void undo_e8(std::vector<uint8_t>& data, size_t start, size_t len, size_t abs_start,
             int32_t filesize) {
    if (len <= 10) return;
    size_t i = 0;
    int64_t curpos = static_cast<int64_t>(abs_start);
    const size_t limit = len - 10;
    while (i < limit) {
        if (data[start + i] != 0xE8) {
            ++i;
            ++curpos;
            continue;
        }
        uint8_t* p = data.data() + start + i + 1;
        int32_t abs_off = static_cast<int32_t>(uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
                                               (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24));
        if (abs_off >= -curpos && abs_off < filesize) {
            const int32_t rel = (abs_off >= 0) ? static_cast<int32_t>(abs_off - curpos)
                                               : static_cast<int32_t>(abs_off + filesize);
            const uint32_t u = static_cast<uint32_t>(rel);
            p[0] = uint8_t(u);
            p[1] = uint8_t(u >> 8);
            p[2] = uint8_t(u >> 16);
            p[3] = uint8_t(u >> 24);
        }
        i += 5;
        curpos += 5;
    }
}

// One CE ROM block: u32 window bits, u32 decoded size, 8 reserved bytes, then
// the LZX stream. Appends the decoded bytes to `out`.
bool ce_block(std::span<const uint8_t> blob, std::vector<uint8_t>& out, size_t cap) {
    if (blob.size() < 16) return false;
    auto rd = [&](size_t o) {
        return uint32_t(blob[o]) | (uint32_t(blob[o + 1]) << 8) | (uint32_t(blob[o + 2]) << 16) |
               (uint32_t(blob[o + 3]) << 24);
    };
    const uint32_t window_bits = rd(0);
    const uint32_t want = rd(4);
    if (!LzxDecoder::window_ok(window_bits)) return false;
    if (want == 0 || want > cap) return false;

    LzxDecoder d(blob.subspan(16), window_bits, want + kMaxMatch);
    if (!d.read_header()) return false;
    if (!d.decode_until(want)) return false;
    d.out.resize(want);
    if (d.intel_started()) undo_e8(d.out, 0, d.out.size(), 0, d.intel_filesize());
    out.insert(out.end(), d.out.begin(), d.out.end());
    return true;
}

uint32_t u24(std::span<const uint8_t> s, size_t off) {
    return uint32_t(s[off]) | (uint32_t(s[off + 1]) << 8) | (uint32_t(s[off + 2]) << 16);
}

}  // namespace

std::optional<std::vector<uint8_t>> ce_decompress_rom(std::span<const uint8_t> src,
                                                      size_t out_len) {
    // Header: a table of 3-byte little-endian values. [0] is the total decoded
    // size; [1..n-1] are the end offsets of each compressed block. Block data
    // starts right after the table.
    constexpr unsigned kBlockBits = 12;  // 4 KiB blocks
    if (src.size() < 3 || out_len == 0) return std::nullopt;

    const uint32_t total = u24(src, 0);
    const size_t num_blocks = total == 0 ? 2 : ((total - 1) >> kBlockBits) + 2;
    if (num_blocks < 2 || num_blocks > (size_t(1) << 22)) return std::nullopt;
    size_t table_end = num_blocks * 3;
    if (table_end > src.size()) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(std::min<size_t>(out_len, size_t(1) << 20));

    size_t block_start = table_end;
    size_t entry = 3;
    size_t remaining = out_len;
    for (size_t b = 1; b < num_blocks && remaining > 0; ++b, entry += 3) {
        const uint32_t block_end = u24(src, entry);
        if (block_end <= block_start || block_end > src.size()) return std::nullopt;
        const size_t before = out.size();
        if (!ce_block(src.subspan(block_start, block_end - block_start), out, remaining))
            return std::nullopt;
        const size_t produced = out.size() - before;
        if (produced > remaining) return std::nullopt;
        remaining -= produced;
        block_start = block_end;
    }

    if (out.empty()) return std::nullopt;
    // A blob may declare fewer bytes than the caller's field (a module .data
    // section whose tail is zero-filled at load time); pad rather than fail.
    out.resize(out_len, 0);
    return out;
}

std::optional<std::vector<uint8_t>> lzx_decompress_cab(std::span<const uint8_t> src, size_t out_len,
                                                       unsigned window_bits) {
    if (!LzxDecoder::window_ok(window_bits) || out_len == 0) return std::nullopt;

    LzxDecoder d(src, window_bits, out_len + kMaxMatch);
    if (!d.read_header()) return std::nullopt;

    // Output is produced in 32 KiB frames. Two rules apply at every frame
    // boundary: the bitstream is padded to the next 16-bit word, and the x86
    // translation runs over that frame's bytes using their absolute position
    // (for the first 32768 frames only).
    //
    // The translation writes to a copy, never to the decoder's buffer: that
    // buffer doubles as the match window, and later matches must see the
    // untranslated bytes.
    std::vector<uint8_t> out;
    out.reserve(out_len);
    for (size_t frame = 0; out.size() < out_len; ++frame) {
        const size_t done = out.size();
        const size_t want = std::min(kCabFrameSize, out_len - done);
        if (!d.decode_until(done + want)) return std::nullopt;
        out.insert(out.end(), d.out.begin() + static_cast<ptrdiff_t>(done),
                   d.out.begin() + static_cast<ptrdiff_t>(done + want));
        if (d.intel_started() && d.intel_filesize() != 0 && frame < 32768)
            undo_e8(out, done, want, done, d.intel_filesize());
        if (out.size() < out_len) {
            // A match that ran past the boundary would leave the pad bits at an
            // unpredictable position; a conformant stream never emits one.
            if (d.out.size() != done + want) return std::nullopt;
            d.align_frame();
        }
    }
    return out;
}

}  // namespace ft
