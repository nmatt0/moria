// safepath.hpp — write files under a root directory without escaping it.
//
// Firmware images are hostile input: a directory entry may be named "..",
// "/etc/passwd", or a symlink that a later entry writes through. Every path
// here is created by walking components from a root fd with openat + O_NOFOLLOW,
// refusing any component that is absolute, "..", or an existing non-directory
// (a planted symlink). This is the tar-extraction hardening, done once.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ft {

class SafeRoot {
public:
    ~SafeRoot();

    // Open (creating) `dir` as the extraction root. False on failure.
    bool open(const std::string& dir);

    // Create the file at relative `rel` (parents made as needed) and write
    // `data`. Rejects unsafe paths. Returns false on any refusal or IO error.
    bool write_file(const std::string& rel, const std::vector<uint8_t>& data, uint32_t mode);

    // Create a directory (and parents) at relative `rel`.
    bool make_dir(const std::string& rel);

    // Create a symlink at `rel` pointing at `target` (target stored verbatim,
    // never followed by us — writes go through openat/O_NOFOLLOW).
    bool make_symlink(const std::string& rel, const std::string& target);

    const std::string& path() const { return root_path_; }

private:
    // Split rel into sanitized components; false if any is unsafe.
    static bool split(const std::string& rel, std::vector<std::string>& out);
    // Open the directory holding the final component, creating parents. Returns
    // an fd the caller must close, or -1. Sets `leaf` to the final component.
    int open_parent(const std::vector<std::string>& parts, std::string& leaf);

    int root_fd_ = -1;
    std::string root_path_;
};

}  // namespace ft
