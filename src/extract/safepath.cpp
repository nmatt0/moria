#include "extract/safepath.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>

namespace ft {

SafeRoot::~SafeRoot() {
    if (root_fd_ >= 0) ::close(root_fd_);
}

bool SafeRoot::open(const std::string& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    // create_directories returns false (no ec) when the dir already exists; only
    // a real error sets ec.
    if (ec) return false;
    root_fd_ = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd_ < 0) return false;
    root_path_ = dir;
    return true;
}

bool SafeRoot::split(const std::string& rel, std::vector<std::string>& out) {
    out.clear();
    std::string cur;
    auto flush = [&]() -> bool {
        if (cur.empty()) return true;  // collapse //, leading/trailing /
        if (cur == "." ) { cur.clear(); return true; }
        if (cur == "..") return false;  // no escape
        if (cur.find('\0') != std::string::npos) return false;
        out.push_back(cur);
        cur.clear();
        return true;
    };
    for (char c : rel) {
        if (c == '/') {
            if (!flush()) return false;
        } else {
            cur += c;
        }
    }
    if (!flush()) return false;
    return !out.empty();
}

// Open `name` as a subdirectory of `parent_fd`, creating it if absent. Refuses
// to traverse a symlink (O_NOFOLLOW) or a non-directory. Returns the new fd.
static int open_child_dir(int parent_fd, const std::string& name) {
    if (::mkdirat(parent_fd, name.c_str(), 0755) != 0 && errno != EEXIST) return -1;
    return ::openat(parent_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int SafeRoot::open_parent(const std::vector<std::string>& parts, std::string& leaf) {
    leaf = parts.back();
    int fd = ::dup(root_fd_);
    if (fd < 0) return -1;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        int next = open_child_dir(fd, parts[i]);
        ::close(fd);
        if (next < 0) return -1;
        fd = next;
    }
    return fd;
}

bool SafeRoot::write_file(const std::string& rel, const std::vector<uint8_t>& data, uint32_t mode) {
    std::vector<std::string> parts;
    if (!split(rel, parts)) return false;
    std::string leaf;
    int dir_fd = open_parent(parts, leaf);
    if (dir_fd < 0) return false;
    mode_t perm = (mode & 0777) ? (mode & 0777) : 0644;
    int fd = ::openat(dir_fd, leaf.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                      perm);
    ::close(dir_fd);
    if (fd < 0) return false;
    bool ok = true;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) { ok = false; break; }
        off += static_cast<size_t>(n);
    }
    ::close(fd);
    return ok;
}

bool SafeRoot::make_dir(const std::string& rel) {
    std::vector<std::string> parts;
    if (!split(rel, parts)) return false;
    int fd = ::dup(root_fd_);
    if (fd < 0) return false;
    for (const auto& p : parts) {
        int next = open_child_dir(fd, p);
        ::close(fd);
        if (next < 0) return false;
        fd = next;
    }
    ::close(fd);
    return true;
}

bool SafeRoot::make_symlink(const std::string& rel, const std::string& target) {
    if (target.find('\0') != std::string::npos) return false;
    std::vector<std::string> parts;
    if (!split(rel, parts)) return false;
    std::string leaf;
    int dir_fd = open_parent(parts, leaf);
    if (dir_fd < 0) return false;
    // Remove a pre-existing leaf so a planted entry can't be traversed later.
    ::unlinkat(dir_fd, leaf.c_str(), 0);
    int rc = ::symlinkat(target.c_str(), dir_fd, leaf.c_str());
    ::close(dir_fd);
    return rc == 0;
}

}  // namespace ft
