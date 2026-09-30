// wince_hive.cpp — Windows CE registry hive validator. See the header.
#include "validators/wince_hive.hpp"

#include <cstdio>
#include <vector>

#include "wince_hive_parse.hpp"

namespace ft {

namespace {
// Enough recovered records that a coincidental header cannot have produced
// them, and a bound on how many the validator bothers to count.
constexpr size_t kMinValues = 8;
constexpr size_t kCountCap = 4096;
}  // namespace

bool validate_wince_hive(ValidatorCtx& ctx) {
    std::vector<CeHiveValue> values;
    const size_t n = ce_hive_values(ctx.reader, ctx.offset, values, kCountCap);
    if (n < kMinValues) return false;

    ctx.out.size = ctx.reader.size() - ctx.offset;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%zu%s values", n, n >= kCountCap ? "+" : "");
    ctx.out.label = buf;
    std::snprintf(buf, sizeof(buf), "%zu%s registry value record(s) recovered", n,
                  n >= kCountCap ? "+" : "");
    ctx.out.set_confidence(Confidence::Consistent, buf);
    return true;
}

}  // namespace ft
