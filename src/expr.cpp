#include "expr.hpp"

#include <cctype>
#include <stdexcept>

namespace ft {

enum class Op {
    Int, Var,
    Or, And,
    Eq, Ne, Lt, Le, Gt, Ge, In,
    BitOr, BitXor, BitAnd, Shl, Shr,
    Add, Sub, Mul, Div, Mod,
    Not, Neg, BitNot,
};

struct Expr {
    Op op;
    uint64_t ival = 0;
    std::string var;
    ExprPtr a, b, c;
};

namespace {

struct Tok {
    enum Kind { Num, Ident, InKw, DotDot, LParen, RParen, Sym, End } kind;
    std::string text;
    uint64_t num = 0;
};

class Lexer {
public:
    explicit Lexer(const std::string& s) : s_(s) {}

    std::vector<Tok> run() {
        std::vector<Tok> out;
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (std::isspace(static_cast<unsigned char>(c))) { ++i_; continue; }
            if (std::isdigit(static_cast<unsigned char>(c))) { out.push_back(number()); continue; }
            if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') { out.push_back(ident()); continue; }
            if (c == '(') { out.push_back({Tok::LParen, "(", 0}); ++i_; continue; }
            if (c == ')') { out.push_back({Tok::RParen, ")", 0}); ++i_; continue; }
            if (c == '.' && peek(1) == '.') { out.push_back({Tok::DotDot, "..", 0}); i_ += 2; continue; }
            out.push_back(symbol());
        }
        out.push_back({Tok::End, "", 0});
        return out;
    }

private:
    char peek(size_t d) const { return i_ + d < s_.size() ? s_[i_ + d] : '\0'; }

    Tok number() {
        size_t start = i_;
        uint64_t v = 0;
        if (s_[i_] == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
            i_ += 2;
            while (i_ < s_.size() && std::isxdigit(static_cast<unsigned char>(s_[i_]))) {
                char c = s_[i_++];
                int d = (c <= '9') ? c - '0' : (std::tolower(c) - 'a' + 10);
                v = v * 16 + static_cast<uint64_t>(d);
            }
        } else {
            while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_])))
                v = v * 10 + static_cast<uint64_t>(s_[i_++] - '0');
        }
        return {Tok::Num, s_.substr(start, i_ - start), v};
    }

    Tok ident() {
        size_t start = i_;
        while (i_ < s_.size() &&
               (std::isalnum(static_cast<unsigned char>(s_[i_])) || s_[i_] == '_'))
            ++i_;
        std::string t = s_.substr(start, i_ - start);
        if (t == "in") return {Tok::InKw, t, 0};
        return {Tok::Ident, t, 0};
    }

    Tok symbol() {
        static const char* two[] = {"==", "!=", "<=", ">=", "&&", "||", "<<", ">>"};
        for (const char* op : two) {
            if (s_[i_] == op[0] && peek(1) == op[1]) { i_ += 2; return {Tok::Sym, op, 0}; }
        }
        std::string one(1, s_[i_++]);
        return {Tok::Sym, one, 0};
    }

    const std::string& s_;
    size_t i_ = 0;
};

class Parser {
public:
    explicit Parser(std::vector<Tok> toks) : t_(std::move(toks)) {}

    ExprPtr parse() {
        ExprPtr e = parse_or();
        expect(Tok::End);
        return e;
    }

private:
    const Tok& cur() const { return t_[p_]; }
    bool is_sym(const char* s) const { return cur().kind == Tok::Sym && cur().text == s; }
    void advance() { ++p_; }
    void expect(Tok::Kind k) {
        if (cur().kind != k) throw std::runtime_error("expr: unexpected token '" + cur().text + "'");
    }
    static ExprPtr bin(Op op, ExprPtr a, ExprPtr b) {
        auto e = std::make_shared<Expr>();
        e->op = op; e->a = std::move(a); e->b = std::move(b);
        return e;
    }

    ExprPtr parse_or() {
        ExprPtr a = parse_and();
        while (is_sym("||")) { advance(); a = bin(Op::Or, a, parse_and()); }
        return a;
    }
    ExprPtr parse_and() {
        ExprPtr a = parse_cmp();
        while (is_sym("&&")) { advance(); a = bin(Op::And, a, parse_cmp()); }
        return a;
    }
    ExprPtr parse_cmp() {
        ExprPtr a = parse_bitor();
        if (cur().kind == Tok::InKw) {
            advance();
            ExprPtr lo = parse_bitor();
            expect(Tok::DotDot); advance();
            ExprPtr hi = parse_bitor();
            auto e = std::make_shared<Expr>();
            e->op = Op::In; e->a = a; e->b = lo; e->c = hi;
            return e;
        }
        for (;;) {
            Op op;
            if (is_sym("==")) op = Op::Eq;
            else if (is_sym("!=")) op = Op::Ne;
            else if (is_sym("<=")) op = Op::Le;
            else if (is_sym(">=")) op = Op::Ge;
            else if (is_sym("<")) op = Op::Lt;
            else if (is_sym(">")) op = Op::Gt;
            else break;
            advance();
            a = bin(op, a, parse_bitor());
        }
        return a;
    }
    ExprPtr parse_bitor() {
        ExprPtr a = parse_bitxor();
        while (is_sym("|")) { advance(); a = bin(Op::BitOr, a, parse_bitxor()); }
        return a;
    }
    ExprPtr parse_bitxor() {
        ExprPtr a = parse_bitand();
        while (is_sym("^")) { advance(); a = bin(Op::BitXor, a, parse_bitand()); }
        return a;
    }
    ExprPtr parse_bitand() {
        ExprPtr a = parse_shift();
        while (is_sym("&")) { advance(); a = bin(Op::BitAnd, a, parse_shift()); }
        return a;
    }
    ExprPtr parse_shift() {
        ExprPtr a = parse_add();
        for (;;) {
            if (is_sym("<<")) { advance(); a = bin(Op::Shl, a, parse_add()); }
            else if (is_sym(">>")) { advance(); a = bin(Op::Shr, a, parse_add()); }
            else break;
        }
        return a;
    }
    ExprPtr parse_add() {
        ExprPtr a = parse_mul();
        for (;;) {
            if (is_sym("+")) { advance(); a = bin(Op::Add, a, parse_mul()); }
            else if (is_sym("-")) { advance(); a = bin(Op::Sub, a, parse_mul()); }
            else break;
        }
        return a;
    }
    ExprPtr parse_mul() {
        ExprPtr a = parse_unary();
        for (;;) {
            if (is_sym("*")) { advance(); a = bin(Op::Mul, a, parse_unary()); }
            else if (is_sym("/")) { advance(); a = bin(Op::Div, a, parse_unary()); }
            else if (is_sym("%")) { advance(); a = bin(Op::Mod, a, parse_unary()); }
            else break;
        }
        return a;
    }
    ExprPtr parse_unary() {
        if (is_sym("!") || is_sym("-") || is_sym("~")) {
            Op op = is_sym("!") ? Op::Not : is_sym("-") ? Op::Neg : Op::BitNot;
            advance();
            auto e = std::make_shared<Expr>();
            e->op = op; e->a = parse_unary();
            return e;
        }
        return parse_primary();
    }
    ExprPtr parse_primary() {
        if (cur().kind == Tok::LParen) {
            advance();
            ExprPtr e = parse_or();
            expect(Tok::RParen); advance();
            return e;
        }
        if (cur().kind == Tok::Num) {
            auto e = std::make_shared<Expr>();
            e->op = Op::Int; e->ival = cur().num;
            advance();
            return e;
        }
        if (cur().kind == Tok::Ident) {
            auto e = std::make_shared<Expr>();
            e->op = Op::Var; e->var = cur().text;
            advance();
            return e;
        }
        throw std::runtime_error("expr: unexpected token '" + cur().text + "'");
    }

    std::vector<Tok> t_;
    size_t p_ = 0;
};

}  // namespace

ExprPtr parse_expr(const std::string& src) {
    Lexer lex(src);
    Parser parser(lex.run());
    return parser.parse();
}

uint64_t eval_expr(const Expr& e, const Resolver& r) {
    auto L = [&] { return eval_expr(*e.a, r); };
    auto R = [&] { return eval_expr(*e.b, r); };
    switch (e.op) {
        case Op::Int: return e.ival;
        case Op::Var: return r(e.var);
        case Op::Or: return (L() || eval_expr(*e.b, r)) ? 1 : 0;
        case Op::And: return (L() && eval_expr(*e.b, r)) ? 1 : 0;
        case Op::Eq: return L() == R();
        case Op::Ne: return L() != R();
        case Op::Lt: return L() < R();
        case Op::Le: return L() <= R();
        case Op::Gt: return L() > R();
        case Op::Ge: return L() >= R();
        case Op::In: {
            uint64_t v = L();
            return (eval_expr(*e.b, r) <= v && v <= eval_expr(*e.c, r)) ? 1 : 0;
        }
        case Op::BitOr: return L() | R();
        case Op::BitXor: return L() ^ R();
        case Op::BitAnd: return L() & R();
        case Op::Shl: { uint64_t s = R(); return s < 64 ? (L() << s) : 0; }
        case Op::Shr: { uint64_t s = R(); return s < 64 ? (L() >> s) : 0; }
        case Op::Add: return L() + R();
        case Op::Sub: return L() - R();
        case Op::Mul: return L() * R();
        case Op::Div: { uint64_t d = R(); return d ? L() / d : 0; }
        case Op::Mod: { uint64_t d = R(); return d ? L() % d : 0; }
        case Op::Not: return L() ? 0 : 1;
        case Op::Neg: return static_cast<uint64_t>(-static_cast<int64_t>(L()));
        case Op::BitNot: return ~L();
    }
    return 0;
}

void expr_vars_impl(const Expr& e, std::vector<std::string>& out) {
    if (e.op == Op::Var) out.push_back(e.var);
    if (e.a) expr_vars_impl(*e.a, out);
    if (e.b) expr_vars_impl(*e.b, out);
    if (e.c) expr_vars_impl(*e.c, out);
}

std::vector<std::string> expr_vars(const Expr& e) {
    std::vector<std::string> out;
    expr_vars_impl(e, out);
    return out;
}

}  // namespace ft
