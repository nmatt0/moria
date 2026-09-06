#include "tree.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <map>
#include <thread>

#include "file_map.hpp"
#include "reader.hpp"
#include "archives.hpp"
#include "scan.hpp"

namespace ft {

namespace fs = std::filesystem;

bool is_notable(const Finding& f) {
    // Filesystems, containers, executables, bootloaders, device trees, and crypto
    // material (keys/certs) are what an analyst cares about first. Bare
    // compression streams and cpio archives are common enough to be noise.
    const std::string& c = f.category;
    return c == "filesystem" || c == "container" || c == "executable" ||
           c == "bootloader" || c == "dtb" || c == "crypto" || c == "encrypted";
}

namespace {

std::string primary_type(const std::vector<Finding>& findings) {
    // Prefer what the file *is* at its start (offset 0) over anything embedded
    // deeper — a filesystem/kernel that carries an ELF inside is not "an ELF".
    // Among offset-0 findings pick the highest confidence; if none start at 0,
    // fall back to the highest-confidence finding overall.
    const Finding* best = nullptr;
    const Finding* best_at0 = nullptr;
    for (const auto& f : findings) {
        if (!best || f.confidence > best->confidence) best = &f;
        if (f.offset == 0 && (!best_at0 || f.confidence > best_at0->confidence)) best_at0 = &f;
    }
    const Finding* pick = best_at0 ? best_at0 : best;
    return pick ? pick->type : "unknown";
}

FileResult scan_one(const fs::path& path, const fs::path& root,
                    const std::vector<Signature>& sigs, bool list) {
    FileResult fr;
    std::error_code ec;
    fr.path = fs::relative(path, root, ec).string();
    if (fr.path.empty()) fr.path = path.string();

    FileMap fm;
    if (!fm.open(path.string())) {
        fr.ok = false;
        fr.error = fm.error();
        fr.primary_type = "unreadable";
        return fr;
    }
    fr.size = fm.size();
    Reader reader(fm.span());
    fr.findings = scan(reader, sigs);
    if (list)
        for (auto& f : fr.findings) list_members(reader, f);
    fr.primary_type = primary_type(fr.findings);
    return fr;
}

}  // namespace

TreeResult scan_tree(const std::string& root, const std::vector<Signature>& sigs,
                     unsigned nthreads, bool list, const FileSink& sink) {
    TreeResult tr;
    tr.root = root;

    // Collect regular files (do not follow symlinks; skip special files).
    std::vector<fs::path> paths;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_symlink()) {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_regular_file(ec)) paths.push_back(it->path());
    }
    std::sort(paths.begin(), paths.end());

    const size_t n = paths.size();
    tr.file_count = n;
    if (nthreads == 0) nthreads = 1;
    nthreads = std::min<unsigned>(nthreads, std::max<size_t>(1, n));

    // Windowed pipeline: scan a window of files in parallel, then emit that window
    // in path order (updating the aggregates and invoking the sink) before moving
    // on. Memory is bounded to one window of FileResults, not the whole tree, so a
    // 100k-file rootfs never accumulates. Deterministic: emission is path-ordered.
    std::map<std::string, size_t> counts;
    const size_t window = std::max<size_t>(1, nthreads) * 8;
    std::vector<FileResult> win;
    for (size_t base = 0; base < n; base += window) {
        const size_t cnt = std::min(window, n - base);
        win.assign(cnt, FileResult{});
        std::atomic<size_t> next{0};
        auto worker = [&] {
            for (size_t k = next.fetch_add(1); k < cnt; k = next.fetch_add(1))
                win[k] = scan_one(paths[base + k], root, sigs, list);
        };
        const unsigned nw = static_cast<unsigned>(std::min<size_t>(nthreads, cnt));
        std::vector<std::thread> pool;
        for (unsigned t = 0; t < nw; ++t) pool.emplace_back(worker);
        for (auto& th : pool) th.join();

        for (auto& fr : win) {
            counts[fr.primary_type]++;
            tr.bytes += fr.size;
            tr.finding_count += fr.findings.size();
            for (const auto& f : fr.findings) {
                for (const auto& m : f.members) tr.finding_count += m.children.size();
                if (f.category == "crypto") tr.crypto_count++;
                if (is_notable(f)) tr.notable.push_back({fr.path, f});
            }
            if (sink) sink(fr);
        }
    }

    tr.by_type.assign(counts.begin(), counts.end());
    std::sort(tr.by_type.begin(), tr.by_type.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;  // count desc
        return a.first < b.first;                              // then name asc
    });
    return tr;
}

}  // namespace ft
