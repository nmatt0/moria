// expr.hpp — tiny integer expression language for signature constraints and
// size expressions (phase2-design §3.2). Supports field references, integer
// literals (dec / 0xhex), the builtins resolved by the caller (_avail, _offset),
// comparisons, &&/||/!, bit ops, shifts, arithmetic, and `X in LO..HI`.
// Not Turing-complete by design: parse once at load, evaluate per hit.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ft {

struct Expr;
using ExprPtr = std::shared_ptr<Expr>;

// Resolves a variable name to a value. Caller supplies field values + builtins.
using Resolver = std::function<uint64_t(const std::string&)>;

// Parse an expression. Throws std::runtime_error on a syntax error.
ExprPtr parse_expr(const std::string& src);

// Evaluate. Comparisons/logical ops yield 0 or 1.
uint64_t eval_expr(const Expr& e, const Resolver& resolve);

// All variable names referenced (for load-time validation against the layout).
std::vector<std::string> expr_vars(const Expr& e);

}  // namespace ft
