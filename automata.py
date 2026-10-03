"""Hand-written automata pipeline: regex -> NFA -> DFA -> minimized DFA -> matcher."""
import re
from collections import deque

ALPHABET = ["LOGIN_SUCCESS", "LOGIN_FAILED", "PORT_SCAN", "UNAUTHORIZED_ACCESS",
            "SSH_FAIL", "ACCOUNT_LOCKED", "SUSPICIOUS_CMD", "MALWARE_DETECTED", "OTHER"]
EPS = None

# ---------- 1. Regex parser (recursive descent) -> AST ----------
def parse(pattern):
    toks = re.findall(r"[A-Z_]+|\{\d+,\}|[|()*+]", pattern)
    pos = 0
    def peek(): return toks[pos] if pos < len(toks) else None
    def eat():
        nonlocal pos
        pos += 1
        return toks[pos - 1]
    def union():
        node = concat()
        while peek() == "|":
            eat(); node = ("or", node, concat())
        return node
    def concat():
        node = repeat()
        while peek() not in (None, "|", ")"):
            node = ("cat", node, repeat())
        return node
    def repeat():
        node = atom()
        while peek() in ("*", "+") or (peek() or "").startswith("{"):
            t = eat()
            if t == "*": node = ("star", node)
            elif t == "+": node = ("cat", node, ("star", node))
            else:                                   # X{n,} -> X X .. X X*
                out = ("star", node)
                for _ in range(int(t[1:-2])): out = ("cat", node, out)
                node = out
        return node
    def atom():
        if peek() == "(":
            eat(); node = union()
            if peek() != ")": raise ValueError("missing ')' in " + pattern)
            eat(); return node
        t = eat() if peek() else None
        if t not in ALPHABET: raise ValueError(f"unknown token {t!r} in {pattern!r}")
        return ("sym", t)
    ast = union()
    if pos != len(toks): raise ValueError("unexpected input in " + pattern)
    return ast

# ---------- 2. NFA (Thompson's construction) ----------
class NFA:
    def __init__(self): self.trans = {}
    @property
    def n(self): return len(self.trans)
    def new(self):
        self.trans[len(self.trans)] = []
        return len(self.trans) - 1
    def add(self, a, sym, b): self.trans[a].append((sym, b))

def build_nfa(ast):
    nfa = NFA()
    def go(node):
        k = node[0]
        if k == "sym":
            s, e = nfa.new(), nfa.new(); nfa.add(s, node[1], e); return s, e
        if k == "cat":
            s1, e1 = go(node[1]); s2, e2 = go(node[2]); nfa.add(e1, EPS, s2); return s1, e2
        s, e = nfa.new(), nfa.new()
        if k == "or":
            for c in node[1:]:
                cs, ce = go(c); nfa.add(s, EPS, cs); nfa.add(ce, EPS, e)
        else:                                       # star
            cs, ce = go(node[1])
            nfa.add(s, EPS, cs); nfa.add(s, EPS, e); nfa.add(ce, EPS, cs); nfa.add(ce, EPS, e)
        return s, e
    nfa.start, nfa.accept = go(ast)
    return nfa

def closure(nfa, states):
    stack, seen = list(states), set(states)
    while stack:
        for sym, t in nfa.trans[stack.pop()]:
            if sym is EPS and t not in seen: seen.add(t); stack.append(t)
    return frozenset(seen)

def step(nfa, S, a): return closure(nfa, {d for s in S for sym, d in nfa.trans[s] if sym == a})

def nfa_accepts(nfa, toks):
    cur = closure(nfa, {nfa.start})
    for t in toks: cur = step(nfa, cur, t)
    return nfa.accept in cur

# ---------- 3. DFA (subset construction) ----------
class DFA:
    def __init__(self, start, delta, accepting, n):
        self.start, self.delta, self.accepting, self.n = start, delta, accepting, n
    def accepts(self, toks):
        s = self.start
        for t in toks: s = self.delta[(s, t)]
        return s in self.accepting
    def dead_states(self):
        return {s for s in range(self.n) if s not in self.accepting
                and all(self.delta[(s, a)] == s for a in ALPHABET)}
    def table(self):
        dead = self.dead_states()
        return [{"state": s, "start": s == self.start, "accepting": s in self.accepting,
                 "moves": {a: self.delta[(s, a)] for a in ALPHABET if self.delta[(s, a)] not in dead}}
                for s in range(self.n) if s not in dead]

def to_dfa(nfa):
    start = closure(nfa, {nfa.start})
    ids, delta, q = {start: 0}, {}, deque([start])
    while q:
        S = q.popleft()
        for a in ALPHABET:
            T = step(nfa, S, a)
            if T not in ids: ids[T] = len(ids); q.append(T)
            delta[(ids[S], a)] = ids[T]
    return DFA(0, delta, {i for S, i in ids.items() if nfa.accept in S}, len(ids))

# ---------- 4. Minimization (partition refinement) ----------
def minimize(d):
    part = {s: int(s in d.accepting) for s in range(d.n)}
    while True:
        sig = {s: (part[s], tuple(part[d.delta[(s, a)]] for a in ALPHABET)) for s in range(d.n)}
        ids = {}
        new = {s: ids.setdefault(sig[s], len(ids)) for s in range(d.n)}
        if len(ids) == len(set(part.values())): break
        part = new
    delta = {(new[s], a): new[d.delta[(s, a)]] for s in range(d.n) for a in ALPHABET}
    return DFA(new[d.start], delta, {new[s] for s in d.accepting}, len(ids))

# ---------- 5. Matcher: leftmost-longest, non-overlapping ----------
def find_matches(d, toks):
    dead, out, i = d.dead_states(), [], 0
    while i < len(toks):
        s, last = d.start, None
        for j in range(i, len(toks)):
            s = d.delta[(s, toks[j])]
            if s in dead: break
            if s in d.accepting: last = j
        if last is None: i += 1
        else: out.append((i, last)); i = last + 1
    return out

def compile_pattern(pattern):
    nfa = build_nfa(parse(pattern)); dfa = to_dfa(nfa)
    return nfa, dfa, minimize(dfa)
