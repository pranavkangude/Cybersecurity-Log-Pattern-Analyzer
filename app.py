import os
from flask import Flask, Response, jsonify, render_template, request
from automata import compile_pattern
from engine import compile_rules, analyze, HERE, SEV
from diagram import nfa_svg, dfa_svg
import history

app = Flask(__name__)
RULES = compile_rules()   # compiled once at startup

@app.get("/")
def index(): return render_template("index.html")

@app.post("/analyze")
def analyze_route():
    body = request.get_json(silent=True) or {}
    res = analyze(body.get("log", ""), RULES)
    if body.get("save") and res["tokens"]:            # the page asks to save; plain API calls do not
        res["run_id"] = history.save_run(res)
    return jsonify(res)

@app.get("/history")
def history_list():
    return jsonify(runs=history.list_runs(), top_rules=history.top_rules())

@app.get("/history/<int:rid>")
def history_run(rid): return jsonify(history.run_alerts(rid))

@app.delete("/history")
def history_clear():
    history.clear()
    return jsonify(ok=True)

@app.get("/rules")
def rules():
    return jsonify([{**{k: r[k] for k in ("id", "pattern", "name", "severity")},
                     "custom": r.get("custom", False), "window": r.get("window"), "nfa_states": r["nfa"].n, "dfa_states": r["dfa"].n, "min_states": r["mdfa"].n}
                    for r in RULES])

@app.post("/rules")
def add_rule():
    d = request.get_json(silent=True) or {}
    pattern, name, sev = (d.get("pattern") or "").strip(), (d.get("name") or "").strip(), d.get("severity", "MEDIUM")
    if not pattern or not name: return jsonify(error="Enter both a pattern and a name."), 400
    if sev not in SEV: return jsonify(error="Severity must be CRITICAL, HIGH, MEDIUM or LOW."), 400
    win = d.get("window")
    if win in (None, ""): win = None
    else:
        try: win = int(win); assert win > 0
        except (ValueError, TypeError, AssertionError): return jsonify(error="Window must be a whole number of seconds above 0."), 400
    try: nfa, dfa, mdfa = compile_pattern(pattern)
    except ValueError as e: return jsonify(error=str(e)), 400
    rule = {"id": max(r["id"] for r in RULES) + 1, "pattern": pattern, "name": name, "severity": sev,
            "custom": True, "window": win, "nfa": nfa, "dfa": dfa, "mdfa": mdfa}
    RULES.append(rule)       # kept in memory only; restart resets to rules.json
    return jsonify(id=rule["id"]), 201

@app.delete("/rules/<int:rid>")
def remove_rule(rid):
    r = next((r for r in RULES if r["id"] == rid), None)
    if not r or not r.get("custom"): return jsonify(error="Only rules you added can be removed."), 400
    RULES.remove(r)
    return jsonify(ok=True)

@app.get("/automata/<int:rid>")
def automata(rid):
    r = next((r for r in RULES if r["id"] == rid), None)
    if not r: return jsonify(error="no such rule"), 404
    return jsonify(pattern=r["pattern"], table=r["mdfa"].table())

@app.get("/diagram/<int:rid>/<kind>")
def diagram(rid, kind):
    r = next((r for r in RULES if r["id"] == rid), None)
    if not r or kind not in ("nfa", "dfa", "min"): return jsonify(error="not found"), 404
    svg = nfa_svg(r["nfa"]) if kind == "nfa" else dfa_svg(r["dfa"] if kind == "dfa" else r["mdfa"])
    return Response(svg, mimetype="image/svg+xml")

@app.get("/samples")
def samples():
    d = os.path.join(HERE, "sample_logs")
    return jsonify({f: open(os.path.join(d, f)).read() for f in sorted(os.listdir(d))})

if __name__ == "__main__":
    app.run(debug=True)
