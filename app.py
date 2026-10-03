import os
from flask import Flask, Response, jsonify, render_template, request
from engine import compile_rules, analyze, HERE
from diagram import nfa_svg, dfa_svg

app = Flask(__name__)
RULES = compile_rules()   # compiled once at startup

@app.get("/")
def index(): return render_template("index.html")

@app.post("/analyze")
def analyze_route():
    return jsonify(analyze((request.get_json(silent=True) or {}).get("log", ""), RULES))

@app.get("/rules")
def rules():
    return jsonify([{**{k: r[k] for k in ("id", "pattern", "name", "severity")},
                     "nfa_states": r["nfa"].n, "dfa_states": r["dfa"].n, "min_states": r["mdfa"].n}
                    for r in RULES])

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
