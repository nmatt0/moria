// ahocorasick.hpp — multi-pattern byte matcher (Aho-Corasick automaton).
// One pass over the buffer finds every magic of every signature at every
// offset, replacing the M0/M1 O(offsets x signatures) loop. Hand-rolled to
// keep the dependency surface minimal. Reports overlapping matches (a pattern
// that is a suffix of another still fires), matching binwalk's find_overlapping.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace ft {

class AhoCorasick {
public:
    // Register a pattern with a caller-chosen id (ids need not be unique or dense).
    void add(const std::vector<uint8_t>& pattern, uint32_t id);

    // Finalize the automaton. Call once after all add()s, before find().
    void build();

    // Scan data[start..], invoking cb(start_offset, id) for every pattern
    // occurrence in ascending end-position order (overlaps all reported).
    // cb returns false to stop the scan early (used for skip-ahead).
    void find(std::span<const uint8_t> data, size_t start,
              const std::function<bool(size_t, uint32_t)>& cb) const;

private:
    struct Node {
        std::array<int32_t, 256> next;  // goto (total after build())
        int32_t fail = 0;
        std::vector<uint32_t> out_ids;  // pattern ids ending here (incl. suffixes)
        Node() { next.fill(-1); }
    };
    std::vector<Node> nodes_{1};        // node 0 = root
    std::vector<uint32_t> plen_by_id_;  // pattern length per id (indexed by id)
    bool built_ = false;
};

}  // namespace ft
