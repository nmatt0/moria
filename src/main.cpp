// main.cpp — moria CLI (M3).
//   file: prints one JSON object (phase2-design §5.1).
//   dir:  recursively scans and prints a tree object (§5.2). --summary omits
//         the per-file array; --threads sets the worker count.
// Help/usage layout follows the clig.dev conventions (grouped options,
// examples, -h/--help to stdout at exit 0). See moria.1 for the man page.
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>  // _NSGetExecutablePath
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include <algorithm>

#ifndef MORIA_VERSION
#define MORIA_VERSION "dev"
#endif

#include "archives.hpp"
#include "assess.hpp"
#include "carve.hpp"
#include "extract/manifest.hpp"
#include "extract/safepath.hpp"
#include "file_map.hpp"
#include "human.hpp"
#include "json.hpp"
#include "reader.hpp"
#include "resolve.hpp"
#include "scan.hpp"
#include "ubi_info.hpp"
#include "sigload.hpp"
#include "tree.hpp"

namespace {

// Roots under which a signature subdir (`signatures`, `signatures-firmware`,
// `signatures-generated`) may live, in priority order. Covers the build tree,
// an installed FHS layout (<prefix>/bin/moria -> <prefix>/share/moria/<leaf>),
// the per-user XDG data dir, and the system data dirs. This is the G3 fix: the
// binary can be copied to /usr/local/bin and still find its signatures.
// Absolute path to the running executable, or empty if it can't be determined.
// Linux exposes it as /proc/self/exe; macOS uses _NSGetExecutablePath. Only used
// to locate on-disk signature dirs next to an installed binary; the default build
// embeds its signatures, so an empty result here is harmless.
static std::filesystem::path self_exe_path() {
    namespace fs = std::filesystem;
    std::error_code ec;
#if defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);  // query required buffer size
    std::string buf(size, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) != 0) return {};
    fs::path p = fs::weakly_canonical(fs::path(buf.c_str()), ec);
    return ec ? fs::path(buf.c_str()) : p;
#else
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? fs::path{} : p;
#endif
}

std::vector<std::filesystem::path> sig_roots() {
    namespace fs = std::filesystem;
    std::vector<fs::path> roots;
    fs::path exe = self_exe_path();
    if (!exe.empty()) {
        fs::path d = exe.parent_path();
        roots.push_back(d);                          // <exe>/<leaf>
        roots.push_back(d.parent_path());            // build tree: <exe>/../<leaf>
        roots.push_back(d.parent_path() / "share" / "moria");  // install layout
    }
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        roots.push_back(fs::path(xdg) / "moria");
    } else if (const char* home = std::getenv("HOME"); home && *home) {
        roots.push_back(fs::path(home) / ".local" / "share" / "moria");
    }
    roots.push_back("/usr/local/share/moria");
    roots.push_back("/usr/share/moria");
    return roots;
}

std::string find_dir(const std::string& cli, const char* leaf) {
    namespace fs = std::filesystem;
    if (!cli.empty()) return cli;

    std::error_code ec;
    for (const fs::path& root : sig_roots()) {
        fs::path cand = root / leaf;
        if (fs::is_directory(cand, ec)) return cand.string();
    }
    return leaf;  // last-resort: cwd-relative (kept for a plain `./moria` run)
}

std::string find_sig_dir(const std::string& cli) {
    if (cli.empty()) {
        if (const char* env = std::getenv("MORIA_SIGDIR")) return env;
    }
    return find_dir(cli, "signatures");
}

const char* basename_of(const char* argv0) {
    const char* slash = std::strrchr(argv0, '/');
    return slash ? slash + 1 : argv0;
}

void print_help(std::FILE* out, const char* prog, bool color) {
    const char* B = color ? "\033[1m" : "";  // bold section headers on a tty
    const char* R = color ? "\033[0m" : "";
    std::fprintf(out, "Identify and unpack embedded file types in firmware images.\n\n");
    std::fprintf(out, "%sUSAGE%s\n", B, R);
    std::fprintf(out, "  %s [options] <file|dir>\n\n", prog);
    std::fprintf(out, "%sOPTIONS%s\n", B, R);
    std::fprintf(out,
                 "  -j, --json          JSON output (default: human-readable)\n"
                 "  -e, --extract       Extract filesystems and containers to <file>.extracted/\n"
                 "  -c, --carve         Carve raw byte ranges to <file>.carved/, no parsing\n"
                 "  -A, --all           Show findings inside containers/filesystems (default: hidden)\n"
                 "  -E, --entropy       Entropy analysis: unidentified regions + encryption hints\n"
                 "      --broad         Also match ~2500 general (non-firmware) formats\n"
                 "      --list          List archive contents without extracting\n"
                 "  -C, --outdir <DIR>  Output directory for -e / -c\n"
                 "      --depth <N>     Max extraction recursion depth (default: 8)\n"
                 "      --max-files <N> Stop extraction after N files (default: 500000)\n"
                 "      --max-bytes <N> Stop extraction after N bytes (default: 4 GiB)\n"
                 "      --sigs <DIR>    Load signatures from DIR\n"
                 "      --threads <N>   Worker threads for directory scans\n"
                 "  -h, --help          Print help\n"
                 "      --version       Print version\n\n");
    std::fprintf(out, "%sEXAMPLES%s\n", B, R);
    std::fprintf(out,
                 "  %s firmware.bin       Identify a file\n"
                 "  %s -e firmware.bin    Extract its filesystems\n"
                 "  %s ./rootfs/          Scan a directory tree\n\n",
                 prog, prog, prog);
    std::fprintf(out, "Docs: skills/moria/README.md\n");
}

// Recursion budget + guard rails. Extraction is on hostile input, so runaway
// nesting and decompression bombs are bounded: a max depth, an absolute ceiling
// on total files and bytes produced across the whole run, and a per-extraction
// decompression-ratio cap (output/input) that stops descent into a suspicious
// output. When any guard trips, the current branch stops and the manifest is
// marked `capped` — the run still returns what it recovered (never fails out).
struct RecurCtx {
    ft::SafeRoot& root;
    const std::vector<ft::Signature>& sigs;
    ft::Manifest& manifest;
    size_t max_depth;
    size_t max_files;
    uint64_t max_bytes;
    bool all = false;  // -A/--all: don't suppress interior compressed streams
    // running totals
    size_t total_files = 0;
    uint64_t total_bytes = 0;
};

constexpr uint64_t RATIO_FLOOR = 10u << 20;  // only ratio-check outputs above 10 MB
constexpr uint64_t RATIO_LIMIT = 1000;       // output/input > this = likely bomb
constexpr uint64_t MIN_DESCEND = 64;         // never descend into a file smaller than this

void mark_capped(RecurCtx& c, const std::string& why) {
    if (!c.manifest.capped) {  // keep the first reason
        c.manifest.capped = true;
        c.manifest.cap_reason = why;
    }
}

void extract_findings(ft::Reader& reader, const std::vector<ft::Finding>& findings,
                      const std::string& prefix, size_t level, RecurCtx& c);

// Scan an already-produced unsparsed image for embedded filesystems and extract
// each into `parent_sub`/<off>-<type>. Used for Android "super" sparse images,
// which unsparse to many erofs/ext partitions at arbitrary offsets rather than a
// single filesystem at offset 0. Reuses extract_findings so the partitions get
// the same dedup and recursive treatment.
void extract_unsparsed_partitions(const std::string& img_path, const std::string& parent_sub,
                                  size_t level, RecurCtx& c) {
    if (level >= c.max_depth) return;
    ft::FileMap fm;
    if (!fm.open(img_path)) return;
    ft::Reader inner(fm.span());
    auto inner_findings = ft::scan(inner, c.sigs);
    // No nested unsparse: the reconstructed image holds partitions, not sparse.
    std::vector<ft::Finding> parts;
    for (const auto& f : inner_findings)
        if (f.type != "android_sparse") parts.push_back(f);
    extract_findings(inner, parts, parent_sub, level + 1, c);
}

// Re-run extraction on each regular file an extractor produced under `base_sub`,
// one level deeper. This is the recursion: a produced file is scanned with the
// same signatures and its findings extracted, so a gzip-wrapped squashfs, a cpio
// inside a FIT ramdisk, or a filesystem embedded in an extracted blob all unpack.
void descend(const std::string& base_sub, size_t level, RecurCtx& c) {
    namespace fs = std::filesystem;
    if (level > c.max_depth) return;
    const std::string base = c.root.path() + "/" + base_sub;
    std::error_code ec;
    // Snapshot the regular files first: extraction writes new *.extracted dirs
    // into this subtree, and we must not iterate into or reprocess them here (the
    // recursion handles each child dir explicitly).
    std::vector<std::string> files;  // paths relative to the extraction root
    fs::recursive_directory_iterator it(base, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        if (it->is_directory(ec)) {
            // Don't descend the iterator into child extraction dirs or into an
            // unsparsed image's contents (android_sparse handles that itself).
            if (p.filename().string().size() >= 10 &&
                p.filename().string().rfind(".extracted") != std::string::npos)
                it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file(ec) || it->is_symlink(ec)) continue;
        const std::string name = p.filename().string();
        if (name == "manifest.json" || name == "unsparsed.img") continue;
        uintmax_t sz = it->file_size(ec);
        if (ec || sz < MIN_DESCEND) continue;
        files.push_back(fs::relative(p, c.root.path(), ec).string());
    }
    for (const std::string& rel : files) {
        if (c.total_files >= c.max_files) { mark_capped(c, "max-files"); return; }
        if (c.total_bytes >= c.max_bytes) { mark_capped(c, "max-bytes"); return; }
        ft::FileMap fm;
        if (!fm.open(c.root.path() + "/" + rel)) continue;
        ft::Reader r(fm.span());
        auto child = ft::scan(r, c.sigs);
        // Same interior-compression suppression as the top level, so a produced
        // raw-flash blob doesn't re-spawn the internal nodes it contains.
        child = ft::suppress_interior_findings(std::move(child), c.all);
        // Only descend when a finding both has an extractor and cleared the
        // structural bar; a bare magic-tier hit won't spawn a child.
        std::vector<ft::Finding> keep;
        for (const auto& f : child)
            if (ft::find_extractor(f.type) && f.confidence >= static_cast<uint8_t>(ft::Confidence::Structural))
                keep.push_back(f);
        if (keep.empty()) continue;
        extract_findings(r, keep, rel + ".extracted", level, c);
    }
}

// Extract one list of findings (from `reader`) into subdirs under `prefix`, then
// recurse into what was produced. `level` is the current recursion depth (1 =
// the top-level input). Applies the per-filesystem-family dedup and android
// sparse handling, then descends unless a guard trips.
void extract_findings(ft::Reader& reader, const std::vector<ft::Finding>& findings,
                      const std::string& prefix, size_t level, RecurCtx& c) {
    // Some filesystems are reported as several findings because coalescing breaks
    // where embedded file data is independently detected (jffs2 boot-logo PNGs), or
    // because a UBI image's inner UBIFS volume is also detected raw. Those
    // extractors scan from their offset onward, so the lowest-offset finding
    // already covers the later ones. Track coverage per filesystem family and skip
    // a finding once an earlier one covers it (findings arrive offset-ascending).
    // An android_sparse region is unsparsed + inner-extracted in one pass; the same
    // inner FS is also detected raw inside the sparse stream, so skip findings that
    // fall within it.
    // A standalone compressed stream (gzip/xz/zstd/lz4) has no length in its
    // header, so a barely-compressible payload can leave a real-looking signature
    // *inside* the compressed bytes (e.g. gzip storing a squashfs near-verbatim).
    // Once the stream is decompressed we learn its true span (Extracted.consumed)
    // and skip any later finding that falls within it.
    uint64_t jffs2_cov = SIZE_MAX, ubi_cov = SIZE_MAX, exfat_cov = SIZE_MAX, sparse_end = 0,
             comp_end = 0;
    for (const auto& f : findings) {
        ft::Extractor ex = ft::find_extractor(f.type);
        if (!ex) continue;
        if (f.type != "android_sparse" && f.offset < sparse_end) continue;
        const bool is_comp = f.type == "gzip" || f.type == "xz" || f.type == "zstd" ||
                             f.type == "lz4";
        if (!is_comp && f.offset < comp_end) continue;  // inside a compressed stream
        if (f.type == "jffs2") {
            if (f.offset >= jffs2_cov) continue;
            jffs2_cov = f.offset;
        } else if (f.type == "ubi" || f.type == "ubifs") {
            if (f.offset >= ubi_cov) continue;
            ubi_cov = f.offset;
        } else if (f.type == "exfat") {
            if (f.offset >= exfat_cov) continue;
            exfat_cov = f.offset;
        }
        if (c.total_files >= c.max_files) { mark_capped(c, "max-files"); break; }
        if (c.total_bytes >= c.max_bytes) { mark_capped(c, "max-bytes"); break; }

        char off_hex[24];
        std::snprintf(off_hex, sizeof(off_hex), "0x%zx", f.offset);
        const std::string sub =
            prefix.empty() ? std::string(off_hex) + "-" + f.type
                           : prefix + "/" + off_hex + "-" + f.type;
        ft::Extracted e;
        e.depth = level;
        ex(reader, f, c.root, sub, e);
        c.total_files += e.files;
        c.total_bytes += e.bytes;
        if (f.type == "android_sparse" && e.consumed)
            sparse_end = std::max<uint64_t>(sparse_end, f.offset + e.consumed);
        if (is_comp && e.consumed)
            comp_end = std::max<uint64_t>(comp_end, f.offset + e.consumed);
        // A "super" sparse image unsparses to many partitions at various offsets;
        // when no single offset-0 filesystem was found, scan the reconstructed
        // image and extract each embedded partition (a special pass so the
        // unsparsed.img framing is read once, not re-detected by the generic walk).
        const bool scan_unsparsed = f.type == "android_sparse" && e.files == 0;
        // Flag a likely decompression bomb: a large output that dwarfs its input.
        const bool ratio_bomb =
            e.bytes > RATIO_FLOOR && f.size > 0 && e.bytes / f.size > RATIO_LIMIT;
        if (ratio_bomb) {
            e.warnings.push_back("ratio-capped: output/input > " + std::to_string(RATIO_LIMIT));
            // Name the offending entry so a run-level `capped: ratio` is actionable:
            // it means recursion into THIS finding was stopped, not that the whole
            // extraction (which may have recovered everything else) was truncated.
            char loc[80];
            std::snprintf(loc, sizeof(loc), "ratio at %s@0x%llx", f.type.c_str(),
                          static_cast<unsigned long long>(f.offset));
            mark_capped(c, loc);
        }
        // Recursion re-scans every produced file, so a deep level turns up
        // false-positive containers (a file that matched a magic but isn't that
        // format, or a valid header enclosing nothing). Record those only at the
        // top level (where the user pointed moria); below it, keep only
        // extractions that actually produced content.
        const bool produced = e.files || e.dirs || e.symlinks;
        if (level == 1 || produced) c.manifest.entries.push_back(std::move(e));

        if (scan_unsparsed)
            extract_unsparsed_partitions(c.root.path() + "/" + sub + "/unsparsed.img", sub, level, c);
        // Recurse into what this extraction produced, unless a bomb ratio or the
        // depth cap says stop here.
        if (!ratio_bomb && level < c.max_depth) descend(sub, level + 1, c);
    }
}

// Compact human-readable byte count (e.g. "4.0 MB"), for footer notes.
std::string human_bytes(uint64_t n) {
    double b = static_cast<double>(n);
    const char* u = "B";
    for (const char* uu : {"KB", "MB", "GB", "TB"}) {
        if (b < 1024.0) break;
        b /= 1024.0;
        u = uu;
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), (std::strcmp(u, "B") == 0 ? "%.0f %s" : "%.1f %s"), b, u);
    return buf;
}

std::string run_extraction(const std::string& src_path, ft::Reader& reader,
                           const std::vector<ft::Finding>& findings,
                           const std::vector<ft::Signature>& sigs, const std::string& outdir,
                           size_t max_depth, size_t max_files, uint64_t max_bytes, bool all) {
    ft::Manifest manifest;
    manifest.source = src_path;

    ft::SafeRoot root;
    if (!root.open(outdir)) {
        std::fprintf(stderr, "error: cannot create output dir: %s\n", outdir.c_str());
        return "";
    }
    RecurCtx c{root, sigs, manifest, max_depth, max_files, max_bytes, all};
    extract_findings(reader, findings, "", 1, c);

    if (manifest.entries.empty()) return "";
    std::string json = ft::manifest_to_json(manifest);
    std::vector<uint8_t> bytes(json.begin(), json.end());
    root.write_file("manifest.json", bytes, 0644);
    return json;
}

}  // namespace

int main(int argc, char** argv) {
    const auto t_start = std::chrono::steady_clock::now();
    const char* prog = basename_of(argv[0]);
    std::string sig_dir_cli, path;
    unsigned threads = 0;  // 0 -> auto
    bool broad = false;
    bool json_out = false;  // default is the human-readable view
    bool show_all = false;  // -A: don't collapse compressed-stream swarms
    bool entropy = false;   // -E: entropy analysis (unidentified regions + hints)
    bool list = false;
    bool extract = false;
    bool carve = false;
    std::string outdir_cli;
    // Recursion is on by default (depth-capped); --depth 1 = one level only.
    size_t rec_depth = 8;
    size_t rec_max_files = 500000;
    uint64_t rec_max_bytes = uint64_t(4) << 30;
    bool have_path = false;
    bool end_of_opts = false;  // set by "--": everything after is positional

    // Bare invocation is a request for help, not an error (clig convention).
    if (argc == 1) {
        bool color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
        print_help(stdout, prog, color);
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!end_of_opts && std::strcmp(a, "--") == 0) {
            end_of_opts = true;
        } else if (!end_of_opts && (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0)) {
            bool color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
            print_help(stdout, prog, color);
            return 0;
        } else if (!end_of_opts && std::strcmp(a, "--version") == 0) {
            std::printf("%s %s\n", prog, MORIA_VERSION);
            return 0;
        } else if (!end_of_opts && std::strcmp(a, "--sigs") == 0 && i + 1 < argc) {
            sig_dir_cli = argv[++i];
        } else if (!end_of_opts && std::strcmp(a, "--threads") == 0 && i + 1 < argc) {
            threads = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
        } else if (!end_of_opts && std::strcmp(a, "--broad") == 0) {
            broad = true;
        } else if (!end_of_opts && (std::strcmp(a, "--json") == 0 || std::strcmp(a, "-j") == 0)) {
            json_out = true;
        } else if (!end_of_opts && (std::strcmp(a, "--all") == 0 || std::strcmp(a, "-A") == 0)) {
            show_all = true;
        } else if (!end_of_opts && (std::strcmp(a, "--entropy") == 0 || std::strcmp(a, "-E") == 0)) {
            entropy = true;
        } else if (!end_of_opts && (std::strcmp(a, "--human") == 0 || std::strcmp(a, "-H") == 0)) {
            // Human view is the default now; -H/--human is accepted as a no-op
            // so existing invocations keep working.
        } else if (!end_of_opts && std::strcmp(a, "--list") == 0) {
            list = true;
        } else if (!end_of_opts && (std::strcmp(a, "--extract") == 0 || std::strcmp(a, "-e") == 0)) {
            extract = true;
        } else if (!end_of_opts && (std::strcmp(a, "--carve") == 0 || std::strcmp(a, "-c") == 0)) {
            carve = true;
        } else if (!end_of_opts && std::strcmp(a, "--depth") == 0 && i + 1 < argc) {
            unsigned long d = std::strtoul(argv[++i], nullptr, 10);
            rec_depth = d < 1 ? 1 : d;  // depth 1 = one level (no recursion)
        } else if (!end_of_opts && std::strcmp(a, "--max-files") == 0 && i + 1 < argc) {
            rec_max_files = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (!end_of_opts && std::strcmp(a, "--max-bytes") == 0 && i + 1 < argc) {
            rec_max_bytes = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (!end_of_opts && (std::strcmp(a, "--outdir") == 0 || std::strcmp(a, "-C") == 0) &&
                   i + 1 < argc) {
            outdir_cli = argv[++i];
        } else if (!end_of_opts && a[0] == '-' && a[1] != '\0') {
            std::fprintf(stderr, "%s: unknown option '%s'\nTry '%s --help'.\n", prog, a, prog);
            return 2;
        } else if (!have_path) {
            path = a;
            have_path = true;
        } else {
            std::fprintf(stderr, "%s: unexpected argument '%s'\nTry '%s --help'.\n", prog, a, prog);
            return 2;
        }
    }
    if (!have_path) {
        std::fprintf(stderr, "%s: missing <file|dir>\nTry '%s --help'.\n", prog, prog);
        return 2;
    }

    // Signatures are embedded in the binary (self-contained); an explicit --sigs
    // DIR or $MORIA_SIGDIR overrides that with external TOML on disk.
    const char* sig_env = std::getenv("MORIA_SIGDIR");
    const bool external = !sig_dir_cli.empty() || (sig_env && *sig_env);
    ft::LoadResult sigs;
    std::vector<ft::Signature> curated;
    // The curated set is authoritative: its validators decide what its magics mean.
    // The firmware/generated sets carry generic magic-only twins of those formats,
    // so drop any that only duplicate a curated validated magic before appending.
    auto append = [&](ft::LoadResult&& r) {
        ft::drop_redundant_generic_signatures(r.signatures, curated);
        for (auto& s : r.signatures) sigs.signatures.push_back(std::move(s));
        for (auto& e : r.errors) sigs.errors.push_back(std::move(e));
    };
    if (external) {
        sigs = ft::load_signatures(find_sig_dir(sig_dir_cli));
        curated = sigs.signatures;
        if (sig_dir_cli.empty()) {  // $MORIA_SIGDIR: still layer the firmware/generated dirs
            std::error_code fec;
            std::string fw = find_dir("", "signatures-firmware");
            if (std::filesystem::is_directory(fw, fec)) append(ft::load_signatures(fw));
        }
        if (broad) append(ft::load_signatures(find_dir("", "signatures-generated")));
    } else {
        sigs = ft::load_signatures_from_memory(ft::embedded_curated());
        curated = sigs.signatures;
        append(ft::load_signatures_from_memory(ft::embedded_firmware()));
        if (broad) append(ft::load_signatures_from_memory(ft::embedded_generated()));
    }
    for (const auto& err : sigs.errors)
        std::fprintf(stderr, "signature load warning: %s\n", err.c_str());
    if (sigs.signatures.empty()) {
        std::fprintf(stderr, "error: no signatures loaded\n");
        return 1;
    }

    std::error_code ec;
    if (extract && std::filesystem::is_directory(path, ec)) {
        std::fprintf(stderr, "%s: --extract takes a single file, not a directory\n", prog);
        return 2;
    }
    if (carve && std::filesystem::is_directory(path, ec)) {
        std::fprintf(stderr, "%s: --carve takes a single file, not a directory\n", prog);
        return 2;
    }
    if (std::filesystem::is_directory(path, ec)) {
        if (threads == 0) {
            unsigned hw = std::thread::hardware_concurrency();
            threads = hw ? std::min(hw, 16u) : 4u;
        }
        // JSON: stream the `files` array as the scan runs so a huge tree never
        // buffers every file's findings (G7). Human: no per-file output, so the
        // sink is empty and only the bounded aggregates are kept.
        ft::TreeResult tr;
        if (json_out) {
            std::fputs(ft::emit_tree_json_head(path).c_str(), stdout);
            size_t idx = 0;
            tr = ft::scan_tree(path, sigs.signatures, threads, list,
                               [&](const ft::FileResult& fr) {
                                   std::string s = ft::emit_tree_file(fr, idx++);
                                   std::fwrite(s.data(), 1, s.size(), stdout);
                               });
            std::string assessment = ft::assess_tree(tr);
            std::fputs(ft::emit_tree_json_tail(tr, assessment).c_str(), stdout);
            std::fputc('\n', stdout);
        } else {
            tr = ft::scan_tree(path, sigs.signatures, threads, list);
            bool out_color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
            // Plain run-stats footer, mirroring the single-file view (the old
            // header/assessment are dropped; the assessment stays in JSON).
            double b = static_cast<double>(tr.bytes);
            const char* bu = "B";
            for (const char* u : {"KB", "MB", "GB", "TB"}) {
                if (b < 1024.0) break;
                b /= 1024.0;
                bu = u;
            }
            double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
            char buf[512];
            std::snprintf(buf, sizeof(buf),
                          "Files analyzed:  %zu\nBytes analyzed:  %.*f %s\nFindings:        %zu\n"
                          "Elapsed:         %.3f s\n",
                          tr.file_count, (std::strcmp(bu, "B") == 0 ? 0 : 1), b, bu,
                          tr.finding_count, secs);
            std::printf("%s", ft::emit_tree_human(tr, buf, out_color, show_all).c_str());
        }
        return 0;
    }

    ft::FileMap fm;
    if (!fm.open(path)) {
        std::fprintf(stderr, "error: %s\n", fm.error().c_str());
        return 1;
    }
    ft::Reader reader(fm.span());
    auto findings = ft::scan(reader, sigs.signatures);
    if (list)
        for (auto& f : findings) ft::list_members(reader, f);
    // Drop interior findings (anything strictly inside a filesystem/container)
    // unless -A. Applies to both the identify output
    // and extraction below, so neither vomits hundreds of internal fs nodes.
    // Collapse each UBI into one finding carrying its named volumes (unless -A),
    // then drop findings that live inside a filesystem/container (its own
    // extractor owns them: fs data nodes, a boot image's kernel/ramdisk, and
    // spurious magic hits inside compressed data).
    findings = ft::enrich_ubi_findings(reader, std::move(findings), show_all);
    size_t hidden_interior = 0;
    findings = ft::suppress_interior_findings(std::move(findings), show_all, &hidden_interior);
    // Entropy analysis (unidentified regions + high-entropy hints) is opt-in via
    // -E. It is region-aware, so a filesystem's compressed interior is not
    // mistaken for "possible encryption". Off by default keeps the output about
    // what moria identified, not a wall of entropy readouts.
    std::vector<ft::Region> regions;
    double ent = 0.0;
    if (entropy) {
        regions = ft::unidentified_regions(reader, findings, 4096);
        ent = ft::whole_file_entropy(reader);
    }
    std::string assessment = ft::assess_file(findings, fm.size(), regions, ent, entropy);
    if (hidden_interior > 0)
        assessment += " (" + std::to_string(hidden_interior) +
                      " interior findings hidden; -A to show)";
    std::string extraction;
    std::string outdir;
    if (extract) {
        outdir = outdir_cli.empty() ? path + ".extracted" : outdir_cli;
        extraction = run_extraction(path, reader, findings, sigs.signatures, outdir, rec_depth,
                                    rec_max_files, rec_max_bytes, show_all);
    }
    // Carve (`-c`): dump each finding's raw byte range (and the unidentified gaps)
    // to disk without parsing, so a researcher gets the bytes even when extraction
    // fails. Independent of -e; when both run, carve gets a sibling `.carved` dir.
    ft::CarveResult cr;
    if (carve) {
        std::string cdir = outdir_cli.empty() ? path + ".carved"
                                              : (extract ? outdir_cli + ".carved" : outdir_cli);
        cr = ft::carve(path, reader, findings, cdir, show_all, rec_max_bytes);
    }
    if (json_out) {
        std::printf("%s\n",
                    ft::emit_file_json(path, fm.size(), findings, regions, assessment, extraction)
                        .c_str());
    } else {
        bool out_color = isatty(fileno(stdout)) && !std::getenv("NO_COLOR");
        // Plain run-stats footer (replaces the old header/assessment lines).
        size_t nfind = findings.size();
        for (const auto& f : findings)
            for (const auto& m : f.members) nfind += m.children.size();
        double b = static_cast<double>(fm.size());
        const char* bu = "B";
        for (const char* u : {"KB", "MB", "GB", "TB"}) {
            if (b < 1024.0) break;
            b /= 1024.0;
            bu = u;
        }
        double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
        char buf[512];
        std::string footer;
        if (!extraction.empty()) footer += "-> extracted to " + outdir + "/\n";
        if (carve && cr.regions_written > 0) {
            footer += "-> carved " + std::to_string(cr.regions_written) +
                      (cr.regions_written == 1 ? " region (" : " regions (") +
                      human_bytes(cr.bytes_written) + ") to " + cr.outdir + "/";
            if (cr.skipped_unknown > 0)
                footer += "; " + std::to_string(cr.skipped_unknown) + " unknown-size skipped";
            if (cr.capped) footer += "; capped at --max-bytes";
            footer += "\n";
        } else if (carve) {
            footer += "-> nothing to carve\n";
        }
        if (hidden_interior > 0)
            footer += std::to_string(hidden_interior) +
                      " interior findings hidden (-A to show)\n";
        std::snprintf(buf, sizeof(buf),
                      "Files analyzed:  1\nBytes analyzed:  %.*f %s\nFindings:        %zu\n"
                      "Elapsed:         %.3f s\n",
                      (std::strcmp(bu, "B") == 0 ? 0 : 1), b, bu, nfind, secs);
        footer += buf;
        std::printf("%s", ft::emit_file_human(findings, regions, footer, out_color, show_all).c_str());
    }
    return 0;
}
