# Cybersecurity Log Pattern Analyzer

An Automata Theory / Theory of Computation project. Attack signatures are written as **regular expressions** over log events. Our own code compiles each one into an **NFA** (Thompson's construction), converts it to a **DFA** (subset construction), **minimizes** it, and scans logs with it to raise security alerts. No automata libraries and no ML dataset are used.

```
Log -> Tokenizer -> Regex rule -> NFA -> DFA -> Minimized DFA -> Matcher -> Alert
```

## Features
- Regex parser for tokens with `space` (then), `|`, `*`, `+`, `{n,}` and `( )`
- NFA, DFA and minimized DFA, drawn as diagrams or shown as tables in the web page
- 11 built-in rules, plus rules you add live from the browser
- Per-source streams (events from different IPs never mix)
- Optional time windows, such as 5 failures within 60 seconds
- SQLite alert history
- 12 automated tests, including a cross-check against Python's `re` module

## Run
```
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python app.py                  # open http://127.0.0.1:5000
python -m pytest               # expect: 12 passed
```

## Log format
One event per line, either `EVENT` or `time, source, EVENT`, for example `2026-09-30 10:00:05, 10.0.0.5, LOGIN_FAILED`.
Events: LOGIN_SUCCESS, LOGIN_FAILED, PORT_SCAN, UNAUTHORIZED_ACCESS, SSH_FAIL, ACCOUNT_LOCKED, SUSPICIOUS_CMD, MALWARE_DETECTED. Anything else becomes OTHER.

## Files
| File | Purpose |
|---|---|
| `automata.py` | Parser, NFA, DFA, minimization, matcher |
| `engine.py` | Tokenizer, rule compilation, alerts |
| `diagram.py` | SVG diagrams of the automata |
| `history.py` | SQLite alert history (`history.db`, created automatically) |
| `app.py` | Flask routes |
| `rules.json` | Built-in rules |
| `sample_logs/` | Example logs |
| `tests/` | pytest tests |

## Design decisions
- Matches are leftmost-longest and non-overlapping. Each alert reports "events in match".
- Overlapping rules (for example 1 and 2) both fire; the longer pattern has higher severity.
- A `window` is a stopwatch beside the DFA, not part of it: a clock is extra memory a pure DFA does not have.
- Rules added in the browser are kept in memory and reset on restart.

## Limitations
Signature-based only (unknown attacks are missed), and regular languages cannot count over unbounded history. Future work: live log tailing and ML anomaly detection.
