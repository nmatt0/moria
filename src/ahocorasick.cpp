#include "ahocorasick.hpp"

#include <queue>

namespace ft {

void AhoCorasick::add(const std::vector<uint8_t>& pattern, uint32_t id) {
    int32_t cur = 0;
    for (uint8_t b : pattern) {
        if (nodes_[cur].next[b] == -1) {
            nodes_[cur].next[b] = static_cast<int32_t>(nodes_.size());
            nodes_.emplace_back();
        }
        cur = nodes_[cur].next[b];
    }
    if (id >= plen_by_id_.size()) plen_by_id_.resize(id + 1, 0);
    plen_by_id_[id] = static_cast<uint32_t>(pattern.size());
    nodes_[cur].out_ids.push_back(id);
}

void AhoCorasick::build() {
    std::queue<int32_t> q;
    // Depth-1 nodes fail to root; missing root edges loop back to root.
    for (int c = 0; c < 256; ++c) {
        int32_t v = nodes_[0].next[c];
        if (v == -1) {
            nodes_[0].next[c] = 0;
        } else {
            nodes_[v].fail = 0;
            q.push(v);
        }
    }
    // BFS: complete the goto function and compute fail + merged outputs.
    while (!q.empty()) {
        int32_t u = q.front();
        q.pop();
        for (int c = 0; c < 256; ++c) {
            int32_t v = nodes_[u].next[c];
            if (v == -1) {
                nodes_[u].next[c] = nodes_[nodes_[u].fail].next[c];
            } else {
                nodes_[v].fail = nodes_[nodes_[u].fail].next[c];
                const auto& suffix_out = nodes_[nodes_[v].fail].out_ids;
                nodes_[v].out_ids.insert(nodes_[v].out_ids.end(), suffix_out.begin(),
                                         suffix_out.end());
                q.push(v);
            }
        }
    }
    built_ = true;
}

void AhoCorasick::find(std::span<const uint8_t> data, size_t start,
                       const std::function<bool(size_t, uint32_t)>& cb) const {
    if (!built_) return;
    int32_t state = 0;
    for (size_t i = start; i < data.size(); ++i) {
        state = nodes_[state].next[data[i]];
        for (uint32_t id : nodes_[state].out_ids) {
            const size_t len = plen_by_id_[id];
            if (!cb(i + 1 - len, id)) return;  // start offset of this match
        }
    }
}

}  // namespace ft
