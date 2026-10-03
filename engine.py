"""Tokenizer, rule compilation and alert generation."""
import json, os
from automata import ALPHABET, compile_pattern, find_matches

SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
HERE = os.path.dirname(os.path.abspath(__file__))

def tokenize(text):
    """Accepts 'timestamp, source, EVENT' or just 'EVENT' per line -> [(token, source, line_no)]."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip(): continue
        p = [x.strip() for x in line.split(",")]
        src, ev = (p[1], p[2]) if len(p) >= 3 else ("-", p[-1])
        ev = ev.upper()
        out.append((ev if ev in ALPHABET else "OTHER", src, n))
    return out

def compile_rules(path=None):
    rules = json.load(open(path or os.path.join(HERE, "rules.json")))
    for r in rules:
        r["nfa"], r["dfa"], r["mdfa"] = compile_pattern(r["pattern"])
    return rules

def analyze(text, rules):
    toks = tokenize(text)
    streams = {}
    for t in toks: streams.setdefault(t[1], []).append(t)   # one stream per source
    alerts = []
    for src, stream in streams.items():
        names = [t[0] for t in stream]
        for r in rules:
            for a, b in find_matches(r["mdfa"], names):
                alerts.append({"id": r["id"], "rule": r["name"], "severity": r["severity"],
                               "source": src, "events": b - a + 1,
                               "start": stream[a][2], "end": stream[b][2],
                               "lines": f"{stream[a][2]}-{stream[b][2]}"})
    alerts.sort(key=lambda x: (SEV[x["severity"]], x["start"]))
    return {"tokens": [{"token": t, "source": s, "line": n} for t, s, n in toks], "alerts": alerts}
