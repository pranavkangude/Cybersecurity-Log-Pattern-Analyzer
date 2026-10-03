# Cybersecurity Log Pattern Analyzer (prototype)

Regex rules -> NFA (Thompson) -> DFA (subset construction) -> minimized DFA -> leftmost-longest matcher -> alerts.
All automata code is in `automata.py` and uses no automata libraries.

## Run
```
pip install -r requirements.txt
python app.py          # open http://127.0.0.1:5000
python -m pytest       # tests, including a cross-check against Python's re module
```

## Files
- `automata.py`: parser, NFA, DFA, minimization, matcher
- `engine.py`: tokenizer, rule compilation, alerts (one token stream per source IP)
- `diagram.py`: SVG diagrams of the NFA, DFA and minimized DFA
- `app.py`: Flask routes `/`, `/analyze`, `/rules` (GET and POST), `/rules/<id>` (DELETE), `/automata/<id>`, `/diagram/<id>/<nfa|dfa|min>`, `/samples`
- `rules.json`: the 8 rules; edit to add more
- `sample_logs/`, `tests/`

## Decisions
- Matches are leftmost-longest and non-overlapping; each alert shows "Events in match".
- Overlapping rules (1 and 2) both fire; Rule 2 is CRITICAL.
- Diagrams are drawn by `diagram.py` as SVG (no Graphviz needed). Rule 10 shows union and grouping.
- Rules can be added from the web page. They are validated, compiled live, and kept in memory only (a restart resets to `rules.json`).
- A rule may have an optional `window` (seconds): a match may not span more than that between its first and last event. Needs `time, source, EVENT` lines with timestamps like `2026-09-30 10:00:05`. Rule 11 is an example.
- Not yet built: SQLite, live log tailing.
