"""SQLite alert history (uses Python's built-in sqlite3, nothing to install)."""
import os, sqlite3
from contextlib import closing
from datetime import datetime
from engine import HERE

def _db():
    c = sqlite3.connect(os.environ.get("LOG_ANALYZER_DB", os.path.join(HERE, "history.db")))
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, events INTEGER, alert_count INTEGER);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER REFERENCES runs(id),
            rule TEXT, severity TEXT, source TEXT, events INTEGER, lines TEXT);""")
    return c

def save_run(result):
    with closing(_db()) as c, c:
        cur = c.execute("INSERT INTO runs(created, events, alert_count) VALUES (?,?,?)",
                        (datetime.now().isoformat(timespec="seconds", sep=" "), len(result["tokens"]), len(result["alerts"])))
        c.executemany("INSERT INTO alerts(run_id, rule, severity, source, events, lines) VALUES (?,?,?,?,?,?)",
                      [(cur.lastrowid, a["rule"], a["severity"], a["source"], a["events"], a["lines"]) for a in result["alerts"]])
        return cur.lastrowid

def list_runs(limit=20):
    with closing(_db()) as c:
        return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

def run_alerts(run_id):
    with closing(_db()) as c:
        return [dict(r) for r in c.execute(
            "SELECT rule, severity, source, events, lines FROM alerts WHERE run_id=? ORDER BY id", (run_id,))]

def top_rules(limit=5):
    with closing(_db()) as c:
        return [dict(r) for r in c.execute(
            "SELECT rule, severity, COUNT(*) AS n FROM alerts GROUP BY rule, severity ORDER BY n DESC, rule LIMIT ?", (limit,))]

def clear():
    with closing(_db()) as c, c:
        c.execute("DELETE FROM alerts"); c.execute("DELETE FROM runs")
