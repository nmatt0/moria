// nilfs2.cpp — NILFS2 read-only extraction. See nilfs2.hpp.
//
// Format reference: the kernel on-disk header (uapi/linux/nilfs2_ondisk.h) and
// fs/nilfs2 (bmap/btree/alloc/cpfile). Everything is little-endian.
//
// Read chain (validated against a real mkfs.nilfs2 image):
//   1. Two superblocks (primary at 1024, secondary near EOF). Pick the valid one
//      with the greater s_wtime; it names the last partial segment and the last
//      checkpoint number.
//   2. The super root is the last block of that partial segment; it embeds the
//      DAT, cpfile and sufile inodes directly.
//   3. DAT (disk address translation) is a palloc file whose own block map uses
//      physical pointers. dat_translate(vblocknr) reads DAT entry vblocknr and
//      returns its physical block.
//   4. cpfile is an mdt file (header + checkpoint array); checkpoint s_last_cno
//      embeds the ifile inode.
//   5. ifile is a palloc file of inodes; read inode NILFS_ROOT_INO (2) and walk.
//
// Block mapping (nilfs_bmap): the inode's 56-byte i_bmap holds either a "direct"
// map (header + up to 6 pointers for file blocks 0..5) or a B-tree root (flag
// NILFS_BMAP_LARGE). B-tree non-root nodes carry an 8-byte pad between header and
// keys. Pointers are physical for the DAT inode and virtual (DAT-translated) for
// every other inode.
#include "extract/nilfs2.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t NILFS_MAGIC = 0x3434;
constexpr uint64_t SB_OFFSET = 1024;
constexpr uint32_t ROOT_INO = 2;
constexpr uint32_t SEGSUM_MAGIC = 0x1eaffa11;

// inode layout
constexpr uint64_t I_SIZE_OFF = 8;
constexpr uint64_t I_MODE_OFF = 48;
constexpr uint64_t I_BMAP_OFF = 56;
constexpr uint64_t I_BMAP_BYTES = 56;  // NILFS_BMAP_SIZE (7 * 8)

// bmap
constexpr uint8_t BMAP_LARGE = 0x1;                 // i_bmap[0] low byte: B-tree if set
constexpr unsigned DIRECT_NBLOCKS = 6;              // direct keys 0..5 at i_bmap[1..6]
constexpr uint64_t BT_NODE_HDR = 8;                 // struct nilfs_btree_node
constexpr uint64_t BT_EXTRA_PAD = 8;                // non-root key pad
constexpr int BT_ROOT_NCMAX = 3;                    // (56 - 8) / 16

// file mode bits
constexpr uint16_t S_IFMT = 0xF000;
constexpr uint16_t S_IFREG = 0x8000;
constexpr uint16_t S_IFDIR = 0x4000;
constexpr uint16_t S_IFLNK = 0xA000;

// cpfile header is 32 bytes; checkpoint.cp_ifile_inode sits at offset 64.
constexpr uint64_t CPFILE_HDR = 32;
constexpr uint64_t CP_IFILE_INODE_OFF = 64;

// Guardrails.
constexpr size_t MAX_FILES = 2000000;
constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_BTREE_NODES = 1u << 20;
constexpr size_t MAX_BLOCKS_PER_FILE = 1u << 22;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;

std::optional<uint8_t> rd8(const Reader& r, uint64_t o) {
    return r.at<uint8_t>(static_cast<size_t>(o), Endian::Little);
}
std::optional<uint16_t> rd16(const Reader& r, uint64_t o) {
    return r.at<uint16_t>(static_cast<size_t>(o), Endian::Little);
}
std::optional<uint32_t> rd32(const Reader& r, uint64_t o) {
    return r.at<uint32_t>(static_cast<size_t>(o), Endian::Little);
}
std::optional<uint64_t> rd64(const Reader& r, uint64_t o) {
    return r.at<uint64_t>(static_cast<size_t>(o), Endian::Little);
}

struct Ctx {
    const Reader& r;
    uint64_t base = 0;        // absolute file offset of block 0
    uint64_t bs = 0;
    uint16_t inode_size = 0;
    uint16_t dat_entry_size = 0;
    uint16_t checkpoint_size = 0;
    uint64_t block_count = 0;  // device size in blocks (bound for ptrs)
    int bt_node_ncmax = 0;     // B-tree children per full block node
    SafeRoot* root = nullptr;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t files_seen = 0;
    // DAT file-block -> physical block, and ifile file-block -> virtual block.
    std::unordered_map<uint64_t, uint64_t> dat_map{};
    std::unordered_map<uint64_t, uint64_t> ifile_map{};
    std::unordered_set<uint64_t> dir_stack{};  // inode recursion cycle guard
};

uint64_t blk_off(const Ctx& c, uint64_t b) { return c.base + b * c.bs; }

// Collect a bmap into {file_block -> pointer}. For the DAT inode pointers are
// physical and `translate` is identity; for other inodes pointers are virtual
// and `translate` maps a virtual block to a physical one (to descend B-tree
// index nodes). Leaf pointers are stored raw (the caller translates them).
template <class Translate>
void collect_bmap(Ctx& c, uint64_t inode_off, Translate translate,
                  std::unordered_map<uint64_t, uint64_t>& out) {
    const uint64_t bmap = inode_off + I_BMAP_OFF;
    auto flags = rd8(c.r, bmap);
    if (!flags) { c.truncated = true; return; }

    if ((*flags & BMAP_LARGE) == 0) {
        // Direct: pointer for key k at i_bmap[1 + k].
        for (unsigned k = 0; k < DIRECT_NBLOCKS; ++k) {
            auto p = rd64(c.r, bmap + 8 + uint64_t(k) * 8);
            if (p && *p != 0) out[k] = *p;
        }
        return;
    }

    // B-tree. Root node is inline in i_bmap (no pad); block nodes carry an
    // 8-byte pad between header and keys.
    size_t nodes = 0;
    struct Frame { uint64_t off; bool is_root; int level; int ncmax; };
    std::vector<Frame> stack;
    auto level = rd8(c.r, bmap + 1);
    if (!level || *level == 0) { c.truncated = true; return; }
    stack.push_back({bmap, true, *level, BT_ROOT_NCMAX});

    while (!stack.empty()) {
        Frame f = stack.back();
        stack.pop_back();
        if (++nodes > MAX_BTREE_NODES || out.size() > MAX_BLOCKS_PER_FILE) {
            c.truncated = true;
            return;
        }
        auto nch = rd16(c.r, f.off + 2);
        if (!nch) { c.truncated = true; continue; }
        const uint64_t dkeys = f.off + BT_NODE_HDR + (f.is_root ? 0 : BT_EXTRA_PAD);
        const uint64_t dptrs = dkeys + uint64_t(f.ncmax) * 8;
        int n = *nch;
        if (f.is_root && n > BT_ROOT_NCMAX) { n = BT_ROOT_NCMAX; c.truncated = true; }
        if (!f.is_root && n > f.ncmax) { n = f.ncmax; c.truncated = true; }
        for (int i = 0; i < n; ++i) {
            auto key = rd64(c.r, dkeys + uint64_t(i) * 8);
            auto ptr = rd64(c.r, dptrs + uint64_t(i) * 8);
            if (!key || !ptr) { c.truncated = true; break; }
            if (f.level == 1) {
                out[*key] = *ptr;  // leaf: file block -> data block pointer
            } else {
                uint64_t child = translate(*ptr);
                if (child == 0 || child >= c.block_count) { c.truncated = true; continue; }
                stack.push_back({blk_off(c, child), false, f.level - 1, c.bt_node_ncmax});
            }
        }
    }
}

// palloc: byte position of entry `nr` (entry size `es`) within its file -> the
// file block offset and the byte offset inside that block.
void palloc_pos(const Ctx& c, uint64_t nr, uint64_t es, uint64_t& fblk, uint64_t& boff) {
    const uint64_t G = c.bs * 8;             // entries per group (one bitmap block)
    const uint64_t P = c.bs / es;            // entries per block
    const uint64_t D = c.bs / 4;             // groups per descriptor block
    const uint64_t bpg = (G + P - 1) / P + 1;   // entry blocks + 1 bitmap
    const uint64_t bpd = D * bpg + 1;           // + 1 descriptor block
    const uint64_t group = nr / G;
    const uint64_t off = nr % G;
    const uint64_t region = (group / D) * bpd;
    const uint64_t bitmap = region + 1 + (group % D) * bpg;
    fblk = bitmap + 1 + off / P;
    boff = (off % P) * es;
}

// Translate a virtual block number to a physical block via the DAT.
uint64_t dat_translate(Ctx& c, uint64_t vblk) {
    uint64_t fblk, boff;
    palloc_pos(c, vblk, c.dat_entry_size, fblk, boff);
    auto it = c.dat_map.find(fblk);
    if (it == c.dat_map.end()) { c.truncated = true; return 0; }
    auto de_blocknr = rd64(c.r, blk_off(c, it->second) + boff);  // nilfs_dat_entry.de_blocknr @0
    return de_blocknr ? *de_blocknr : 0;
}

// Physical block byte offset for file block `fblk` of a virtual-pointer file.
std::optional<uint64_t> meta_block(Ctx& c, const std::unordered_map<uint64_t, uint64_t>& map,
                                   uint64_t fblk) {
    auto it = map.find(fblk);
    if (it == map.end()) return std::nullopt;
    uint64_t phys = dat_translate(c, it->second);
    if (phys == 0 || phys >= c.block_count) { c.truncated = true; return std::nullopt; }
    return blk_off(c, phys);
}

// Byte offset of inode `ino` within the ifile.
std::optional<uint64_t> read_inode(Ctx& c, uint64_t ino) {
    uint64_t fblk, boff;
    palloc_pos(c, ino, c.inode_size, fblk, boff);
    auto b = meta_block(c, c.ifile_map, fblk);
    if (!b) return std::nullopt;
    return *b + boff;
}

// Read the full content of a regular file / symlink target into `out`.
void read_content(Ctx& c, uint64_t inode_off, uint64_t size, std::vector<uint8_t>& out) {
    if (size > MAX_FILE_BYTES) { size = MAX_FILE_BYTES; c.truncated = true; }
    if (size > c.r.size()) { size = c.r.size(); c.truncated = true; }
    out.assign(static_cast<size_t>(size), 0);
    std::unordered_map<uint64_t, uint64_t> map;
    collect_bmap(c, inode_off, [&](uint64_t v) { return dat_translate(c, v); }, map);
    for (const auto& kv : map) {
        const uint64_t fblk = kv.first;
        const uint64_t start = fblk * c.bs;
        if (start >= size) continue;
        uint64_t phys = dat_translate(c, kv.second);
        if (phys == 0 || phys >= c.block_count) { c.truncated = true; continue; }
        const uint64_t want = std::min<uint64_t>(c.bs, size - start);
        auto span = c.r.bytes(static_cast<size_t>(blk_off(c, phys)), static_cast<size_t>(want));
        if (!span) { c.truncated = true; continue; }
        std::memcpy(out.data() + static_cast<size_t>(start), span->data(),
                    static_cast<size_t>(want));
    }
}

struct DirEnt {
    uint64_t ino;
    std::string name;
};

// Parse the ext2-like directory of an inode into entries.
std::vector<DirEnt> read_dir(Ctx& c, uint64_t inode_off, uint64_t size) {
    std::vector<DirEnt> ents;
    std::unordered_map<uint64_t, uint64_t> map;
    collect_bmap(c, inode_off, [&](uint64_t v) { return dat_translate(c, v); }, map);
    std::vector<uint64_t> fblocks;
    for (const auto& kv : map) fblocks.push_back(kv.first);
    std::sort(fblocks.begin(), fblocks.end());
    for (uint64_t fblk : fblocks) {
        if (fblk * c.bs >= size) break;
        uint64_t phys = dat_translate(c, map[fblk]);
        if (phys == 0 || phys >= c.block_count) { c.truncated = true; continue; }
        const uint64_t base = blk_off(c, phys);
        uint64_t pos = 0;
        while (pos + 12 <= c.bs) {
            auto ino = rd64(c.r, base + pos);
            auto rec_len = rd16(c.r, base + pos + 8);
            auto name_len = rd8(c.r, base + pos + 10);
            if (!ino || !rec_len || !name_len) break;
            if (*rec_len < 12) break;
            if (*ino != 0 && *name_len > 0 && pos + 12 + *name_len <= c.bs) {
                auto nm = c.r.bytes(static_cast<size_t>(base + pos + 12), *name_len);
                if (nm) ents.push_back({*ino, std::string(reinterpret_cast<const char*>(nm->data()),
                                                          nm->size())});
            }
            pos += *rec_len;
        }
    }
    return ents;
}

void walk(Ctx& c, uint64_t ino, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.files_seen++ > MAX_FILES) { c.truncated = true; return; }
    if (!c.dir_stack.insert(ino).second) return;  // directory cycle

    auto io = read_inode(c, ino);
    if (!io) { c.truncated = true; c.dir_stack.erase(ino); return; }
    auto dsize = rd64(c.r, *io + I_SIZE_OFF);
    if (!dsize) { c.truncated = true; c.dir_stack.erase(ino); return; }

    for (const DirEnt& e : read_dir(c, *io, *dsize)) {
        if (e.name.empty() || e.name == "." || e.name == "..") continue;
        if (e.name.find('/') != std::string::npos || e.name.find('\0') != std::string::npos)
            continue;
        auto cio = read_inode(c, e.ino);
        if (!cio) { c.truncated = true; continue; }
        auto mode = rd16(c.r, *cio + I_MODE_OFF);
        auto size = rd64(c.r, *cio + I_SIZE_OFF);
        if (!mode || !size) { c.truncated = true; continue; }
        const std::string child_rel = rel.empty() ? e.name : rel + "/" + e.name;
        const std::string full = c.subdir + "/" + child_rel;
        const uint16_t type = *mode & S_IFMT;

        if (type == S_IFDIR) {
            if (c.root && c.root->make_dir(full)) c.out.dirs++;
            walk(c, e.ino, child_rel, depth + 1);
        } else if (type == S_IFLNK) {
            std::vector<uint8_t> buf;
            read_content(c, *cio, std::min<uint64_t>(*size, 4096), buf);
            std::string target(buf.begin(), buf.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && c.root && c.root->make_symlink(full, target)) c.out.symlinks++;
        } else if (type == S_IFREG) {
            std::vector<uint8_t> data;
            read_content(c, *cio, *size, data);
            if (c.root && c.root->write_file(full, data, *mode & 0777)) {
                c.out.files++;
                c.out.bytes += data.size();
            } else if (c.root) {
                c.out.warnings.push_back("write failed: " + child_rel);
            }
        }
    }
    c.dir_stack.erase(ino);
}

// Fill geometry from a superblock at absolute offset `sbo`; false if implausible.
bool parse_super(const Reader& r, uint64_t sbo, Ctx& c, uint64_t& last_cno, uint64_t& last_pseg) {
    auto magic = rd16(r, sbo + 6);
    auto logbs = rd32(r, sbo + 0x14);
    auto devsize = rd64(r, sbo + 0x20);
    auto lcno = rd64(r, sbo + 0x38);
    auto lpseg = rd64(r, sbo + 0x40);
    auto isize = rd16(r, sbo + 0x90);
    auto dsz = rd16(r, sbo + 0x92);
    auto cpsz = rd16(r, sbo + 0x94);
    if (!magic || *magic != NILFS_MAGIC || !logbs || !devsize || !lcno || !lpseg || !isize ||
        !dsz || !cpsz)
        return false;
    if (*logbs > 6) return false;  // 1 KiB .. 64 KiB
    c.bs = uint64_t(1) << (*logbs + 10);
    if (*isize < 128 || *isize > c.bs) return false;
    if (*dsz < 32 || *cpsz < 64) return false;
    c.inode_size = *isize;
    c.dat_entry_size = *dsz;
    c.checkpoint_size = *cpsz;
    c.block_count = *devsize / c.bs;
    c.bt_node_ncmax = static_cast<int>((c.bs - BT_NODE_HDR - BT_EXTRA_PAD) / 16);
    last_cno = *lcno;
    last_pseg = *lpseg;
    return c.block_count > 0;
}

}  // namespace

bool extract_nilfs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "nilfs2";
    out.root = subdir;

    Ctx c{r, f.offset, 0, 0, 0, 0, 0, 0, &root, subdir, out};

    // Pick the valid superblock (primary at 1024, secondary near EOF) with the
    // greater write time; NILFS2 updates them lazily, so the primary can lag.
    uint64_t last_cno = 0, last_pseg = 0;
    uint64_t chosen = SIZE_MAX;
    uint64_t best_wtime = 0;
    {
        Ctx probe{r, f.offset, 0, 0, 0, 0, 0, 0, nullptr, "", out};
        uint64_t cno, pseg;
        for (int which = 0; which < 2; ++which) {
            uint64_t sbo;
            if (which == 0) {
                sbo = f.offset + SB_OFFSET;
            } else {
                auto devsize = rd64(r, f.offset + SB_OFFSET + 0x20);
                if (!devsize || *devsize < 8192) continue;
                sbo = f.offset + (((*devsize >> 12) - 1) << 12);
            }
            Ctx t{r, f.offset, 0, 0, 0, 0, 0, 0, nullptr, "", out};
            if (!parse_super(r, sbo, t, cno, pseg)) continue;
            auto wt = rd64(r, sbo + 0x68);  // s_wtime
            uint64_t w = wt ? *wt : 0;
            if (chosen == SIZE_MAX || w >= best_wtime) {
                best_wtime = w;
                chosen = sbo;
            }
        }
        (void)probe;
    }
    if (chosen == SIZE_MAX || !parse_super(r, chosen, c, last_cno, last_pseg)) {
        out.status = "error:bad-superblock";
        return true;
    }

    // Super root is the last block of the last partial segment.
    const uint64_t ss = blk_off(c, last_pseg);
    auto ssmagic = rd32(r, ss + 8);
    auto ss_nblocks = rd32(r, ss + 0x28);
    if (!ssmagic || *ssmagic != SEGSUM_MAGIC || !ss_nblocks || *ss_nblocks == 0) {
        out.status = "error:segment-summary";
        return true;
    }
    const uint64_t sr = blk_off(c, last_pseg + *ss_nblocks - 1);
    // super_root: sr_sum(4) sr_bytes(2) sr_flags(2) sr_nongc_ctime(8) then inodes.
    const uint64_t dat_inode = sr + 16;
    const uint64_t cpfile_inode = sr + 16 + c.inode_size;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    // DAT block map (physical pointers): the bootstrap for all translation.
    collect_bmap(c, dat_inode, [](uint64_t p) { return p; }, c.dat_map);
    if (c.dat_map.empty()) {
        out.status = "error:dat";
        return true;
    }

    // cpfile: locate checkpoint `last_cno` and read its embedded ifile inode.
    std::unordered_map<uint64_t, uint64_t> cpfile_map;
    collect_bmap(c, cpfile_inode, [&](uint64_t v) { return dat_translate(c, v); }, cpfile_map);
    const uint64_t cps = c.checkpoint_size;
    const uint64_t first = (CPFILE_HDR + cps - 1) / cps;     // mi_first_entry_offset
    const uint64_t per_blk = c.bs / cps;
    if (per_blk == 0) { out.status = "error:cpfile"; return true; }
    const uint64_t tcno = last_cno + first - 1;
    auto cp_block = meta_block(c, cpfile_map, tcno / per_blk);
    if (!cp_block) { out.status = "error:cpfile"; return true; }
    const uint64_t ifile_inode = *cp_block + (tcno % per_blk) * cps + CP_IFILE_INODE_OFF;

    // ifile block map, then walk from the root inode.
    collect_bmap(c, ifile_inode, [&](uint64_t v) { return dat_translate(c, v); }, c.ifile_map);
    if (c.ifile_map.empty()) { out.status = "error:ifile"; return true; }

    walk(c, ROOT_INO, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

size_t nilfs2_probe(const Reader& r, size_t base) {
    Extracted out;
    Ctx c{r, base, 0, 0, 0, 0, 0, 0, nullptr, "", out};
    uint64_t last_cno = 0, last_pseg = 0;
    uint64_t chosen = SIZE_MAX, best = 0;
    for (int which = 0; which < 2; ++which) {
        uint64_t sbo;
        if (which == 0) {
            sbo = base + SB_OFFSET;
        } else {
            auto devsize = rd64(r, base + SB_OFFSET + 0x20);
            if (!devsize || *devsize < 8192) continue;
            sbo = base + (((*devsize >> 12) - 1) << 12);
        }
        Ctx t{r, base, 0, 0, 0, 0, 0, 0, nullptr, "", out};
        uint64_t cno, pseg;
        if (!parse_super(r, sbo, t, cno, pseg)) continue;
        auto wt = rd64(r, sbo + 0x68);
        if (chosen == SIZE_MAX || (wt && *wt >= best)) { best = wt ? *wt : 0; chosen = sbo; }
    }
    if (chosen == SIZE_MAX || !parse_super(r, chosen, c, last_cno, last_pseg)) return 0;

    const uint64_t ss = blk_off(c, last_pseg);
    auto ssmagic = rd32(r, ss + 8);
    auto ss_nblocks = rd32(r, ss + 0x28);
    if (!ssmagic || *ssmagic != SEGSUM_MAGIC || !ss_nblocks || *ss_nblocks == 0) return 0;
    const uint64_t sr = blk_off(c, last_pseg + *ss_nblocks - 1);
    const uint64_t dat_inode = sr + 16;
    const uint64_t cpfile_inode = sr + 16 + c.inode_size;

    collect_bmap(c, dat_inode, [](uint64_t p) { return p; }, c.dat_map);
    if (c.dat_map.empty()) return 0;

    std::unordered_map<uint64_t, uint64_t> cpfile_map;
    collect_bmap(c, cpfile_inode, [&](uint64_t v) { return dat_translate(c, v); }, cpfile_map);
    const uint64_t cps = c.checkpoint_size;
    const uint64_t per_blk = c.bs / cps;
    if (per_blk == 0) return 0;
    const uint64_t tcno = last_cno + (CPFILE_HDR + cps - 1) / cps - 1;
    auto cp_block = meta_block(c, cpfile_map, tcno / per_blk);
    if (!cp_block) return 0;
    const uint64_t ifile_inode = *cp_block + (tcno % per_blk) * cps + CP_IFILE_INODE_OFF;
    collect_bmap(c, ifile_inode, [&](uint64_t v) { return dat_translate(c, v); }, c.ifile_map);

    walk(c, ROOT_INO, "", 0);
    return c.dat_map.size() + c.ifile_map.size();
}

}  // namespace ft
