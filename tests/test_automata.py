import json, random, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from automata import ALPHABET, compile_pattern, nfa_accepts
from engine import compile_rules, analyze

RULES = json.load(open(os.path.join(os.path.dirname(__file__), "..", "rules.json")))
L = {t: chr(65 + i) for i, t in enumerate(ALPHABET)}

def to_py_regex(p): return re.sub(r"[A-Z_]+", lambda m: L[m.group()], p).replace(" ", "")

def test_all_rules_match_python_re():
    rnd = random.Random(1)
    for r in RULES:
        nfa, dfa, mdfa = compile_pattern(r["pattern"])
        rx = re.compile(to_py_regex(r["pattern"]))
        pool = [t for t in ALPHABET if t in r["pattern"]] + ["OTHER"]
        for _ in range(400):
            s = [rnd.choice(pool) for _ in range(rnd.randint(0, 9))]
            want = bool(rx.fullmatch("".join(L[t] for t in s)))
            assert nfa_accepts(nfa, s) == dfa.accepts(s) == mdfa.accepts(s) == want, (r["pattern"], s)

def test_boundaries():
    _, _, m = compile_pattern("LOGIN_FAILED{3,}")
    assert not m.accepts(["LOGIN_FAILED"] * 2)
    assert all(m.accepts(["LOGIN_FAILED"] * n) for n in (3, 4, 10))
    _, _, m6 = compile_pattern("LOGIN_FAILED{5,} ACCOUNT_LOCKED")
    assert not m6.accepts(["LOGIN_FAILED"] * 4 + ["ACCOUNT_LOCKED"])
    assert m6.accepts(["LOGIN_FAILED"] * 5 + ["ACCOUNT_LOCKED"])

def test_minimization_shrinks():
    nfa, dfa, m = compile_pattern("LOGIN_FAILED{3,} LOGIN_SUCCESS")
    assert m.n <= dfa.n < nfa.n

def test_spec_example_and_edge_cases():
    rules = compile_rules()
    res = analyze("LOGIN_SUCCESS\nLOGIN_FAILED\nLOGIN_FAILED\nLOGIN_FAILED\nLOGIN_SUCCESS", rules)
    got = {(a["rule"], a["events"], a["lines"]) for a in res["alerts"]}
    assert got == {("Repeated Login Failures", 3, "2-4"), ("Possible Brute Force", 4, "2-5")}
    assert analyze("", rules)["alerts"] == []
    assert analyze("SOMETHING_ELSE", rules)["tokens"][0]["token"] == "OTHER"

def test_edge_cases_and_new_rules():
    rules = compile_rules()
    names = lambda log: {a["rule"] for a in analyze(log, rules)["alerts"]}
    assert "Repeated Login Failures" in names("LOGIN_FAILED\n" * 3)        # pattern at very start and end
    assert names("OTHER\nOTHER") == set()
    assert "Command Then Malware" in names("SUSPICIOUS_CMD\nMALWARE_DETECTED")
    assert "Scan Then Brute Force" in names("PORT_SCAN\n" * 3 + "LOGIN_FAILED\nSSH_FAIL\nLOGIN_FAILED")
    assert "Scan Then Brute Force" not in names("PORT_SCAN\n" * 3 + "LOGIN_FAILED\nSSH_FAIL")

def test_performance_100k_lines():
    import time
    rules = compile_rules(); rnd = random.Random(2)
    log = "\n".join(rnd.choice(ALPHABET) for _ in range(100_000))
    t = time.time(); analyze(log, rules)
    print("100k lines:", round(time.time() - t, 2), "s")
    assert time.time() - t < 15

def test_diagrams_render():
    from app import app
    c = app.test_client()
    for kind in ("nfa", "dfa", "min"):
        r = c.get(f"/diagram/10/{kind}")
        assert r.status_code == 200 and b"<svg" in r.data

def test_parser_rejects_bad_syntax():
    import pytest
    for bad in ("LOGIN_FAILED{3}", "login_failed", "FOO", "(LOGIN_FAILED", "LOGIN_FAILED $"):
        with pytest.raises(ValueError): compile_pattern(bad)

def test_add_and_remove_rule_at_runtime():
    from app import app
    c = app.test_client()
    bad = c.post("/rules", json={"pattern": "LOGIN_FAILED{3}", "name": "x", "severity": "HIGH"})
    assert bad.status_code == 400 and "error" in bad.get_json()
    ok = c.post("/rules", json={"pattern": "PORT_SCAN{2,} UNAUTHORIZED_ACCESS", "name": "Scan Then Intrusion", "severity": "HIGH"})
    assert ok.status_code == 201
    rid = ok.get_json()["id"]
    res = c.post("/analyze", json={"log": "PORT_SCAN\nPORT_SCAN\nUNAUTHORIZED_ACCESS"}).get_json()
    assert "Scan Then Intrusion" in {a["rule"] for a in res["alerts"]}
    assert c.delete("/rules/1").status_code == 400            # built-in rules are protected
    assert c.delete(f"/rules/{rid}").status_code == 200

def test_time_window_fast_vs_slow():
    rules = compile_rules()
    res = analyze(open(os.path.join(os.path.dirname(__file__), "..", "sample_logs", "fast_vs_slow.log")).read(), rules)
    fast = {(a["rule"], a["source"]) for a in res["alerts"]}
    assert ("Fast Login Failures", "10.0.0.5") in fast        # 5 failures in 20 s
    assert ("Fast Login Failures", "10.0.0.6") not in fast    # 5 failures over 6 minutes
    assert ("Repeated Login Failures", "10.0.0.6") in fast    # the plain rule still fires

def test_time_window_skips_old_events():
    rules = compile_rules()
    log = "\n".join(f"2026-09-30 10:{m}, h, LOGIN_FAILED" for m in
                    ("00:00", "01:40", "01:41", "01:42", "01:43", "01:44"))
    hits = [a for a in analyze(log, rules)["alerts"] if a["rule"] == "Fast Login Failures"]
    assert [(a["start"], a["end"]) for a in hits] == [(2, 6)]  # the old first failure is left out
