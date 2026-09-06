// file_map.hpp — RAII POSIX mmap (zero-copy, MADV_SEQUENTIAL), the substrate
// borrowed from unblob's File. Empty/short files map to an empty span.
#pragma once

#include <cstdint>
#include <span>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ft {

class FileMap {
public:
    FileMap() = default;
    FileMap(const FileMap&) = delete;
    FileMap& operator=(const FileMap&) = delete;
    ~FileMap() {
        if (addr_ && addr_ != MAP_FAILED && len_ > 0) munmap(addr_, len_);
    }

    // Returns false on open/stat/mmap error (message in error()).
    bool open(const std::string& path) {
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            error_ = "open: " + path;
            return false;
        }
        struct stat st{};
        if (fstat(fd, &st) < 0) {
            error_ = "fstat: " + path;
            ::close(fd);
            return false;
        }
        len_ = static_cast<size_t>(st.st_size);
        if (len_ == 0) {
            ::close(fd);
            return true;  // valid, empty span
        }
        addr_ = mmap(nullptr, len_, PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (addr_ == MAP_FAILED) {
            error_ = "mmap: " + path;
            len_ = 0;
            return false;
        }
        madvise(addr_, len_, MADV_SEQUENTIAL);
        return true;
    }

    std::span<const uint8_t> span() const {
        if (!addr_ || addr_ == MAP_FAILED || len_ == 0) return {};
        return {static_cast<const uint8_t*>(addr_), len_};
    }
    size_t size() const { return len_; }
    const std::string& error() const { return error_; }

private:
    void* addr_ = nullptr;
    size_t len_ = 0;
    std::string error_;
};

}  // namespace ft
