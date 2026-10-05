"""
Deliberately vulnerable demo backend.

This exists ONLY to give the WAF something realistic to protect in a
local demo. It is intentionally insecure (string-formatted SQL,
unescaped HTML reflection) -- never deploy this anywhere reachable
from outside localhost, and never put real data behind it.

Run:
    python vulnerable_app.py
It listens on localhost:5000. You're meant to reach it THROUGH the
WAF proxy on :8080, not call it directly.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB = "demo.db"


def ensure_seed_data():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS items (name TEXT)")
    conn.execute("DELETE FROM items")
    conn.executemany("INSERT INTO items VALUES (?)", [("apple",), ("banana",), ("cherry",)])
    conn.commit()
    conn.close()


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    try:
        # Intentionally vulnerable: string-formatted query, on purpose,
        # so the WAF has a real SQL injection target to block.
        query = f"SELECT name FROM items WHERE name LIKE '%{term}%'"
        cur.execute(query)
        rows = cur.fetchall()
        return {"results": [r[0] for r in rows]}
    except Exception as e:
        return {"error": str(e)}, 500
    finally:
        conn.close()


@app.route("/echo")
def echo():
    # Intentionally reflects input unescaped, on purpose, for the XSS demo.
    msg = request.args.get("msg", "")
    return f"<html><body>You said: {msg}</body></html>"


@app.route("/")
def home():
    return "<h3>Demo backend is up. Try /search?q=apple or /echo?msg=hi -- through the WAF on :8080.</h3>"


if __name__ == "__main__":
    ensure_seed_data()
    app.run(port=5000, debug=False)
