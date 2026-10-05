"""
Reverse proxy: every request to this app is inspected by the WAF
before being forwarded to the real backend. This mirrors how a real
WAF (Cloudflare, ModSecurity, AWS WAF) sits in front of an application.

Run (in two separate terminals):
    python ../demo_site/vulnerable_app.py     # the backend, on :5000
    python proxy.py                           # the WAF, on :8080

Then hit http://localhost:8080/ instead of the backend directly.
Dashboard: http://localhost:8080/waf-dashboard
"""

import datetime
from urllib.parse import unquote_plus
from flask import Flask, request, Response
import requests

from waf_core import WAF

BACKEND = "http://localhost:5000"

app = Flask(__name__)
waf = WAF()
recent_log: list[dict] = []


@app.route("/waf-dashboard")
def dashboard():
    rows = "".join(
        f"<tr><td>{r['time']}</td><td>{r['ip']}</td><td>{r['method']}</td>"
        f"<td>{r['path']}</td>"
        f"<td style='color:{'#1a7f37' if r['allowed'] else '#cf222e'}'>"
        f"{'ALLOWED' if r['allowed'] else 'BLOCKED'}</td><td>{r['reason']}</td></tr>"
        for r in reversed(recent_log[-100:])
    )
    return f"""
    <html><head><title>WAF Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
      body {{ font-family: -apple-system, sans-serif; margin: 2rem; background: #fafafa; }}
      h2 {{ margin-bottom: 0.2rem; }}
      table {{ border-collapse: collapse; width: 100%; background: white; }}
      td, th {{ border: 1px solid #e1e4e8; padding: 6px 10px; font-size: 13px; text-align: left; }}
      th {{ background: #f1f3f5; }}
      tr:nth-child(even) {{ background: #f9f9f9; }}
    </style></head>
    <body>
    <h2>WAF Dashboard</h2>
    <p style="color:#666">Auto-refreshes every 5s &middot; showing last 100 requests</p>
    <table><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Result</th><th>Reason</th></tr>
    {rows}
    </table>
    </body></html>
    """


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    client_ip = request.remote_addr
    raw_body = request.get_data(as_text=True)

    # IMPORTANT: decode before scanning. Attackers routinely URL-encode
    # payloads (' -> %27, < -> %3C, etc.) specifically to slip past WAFs
    # that only pattern-match the raw wire bytes. Flask's request.args
    # already decodes query params for us; we use those values rather
    # than the raw query string when building the text the WAF scans.
    decoded_query = " ".join(unquote_plus(v) for v in request.args.values())
    decoded_body = unquote_plus(raw_body)

    decision = waf.inspect(
        client_ip=client_ip,
        method=request.method,
        path="/" + path,
        query_string=decoded_query,
        body=decoded_body,
        headers=dict(request.headers),
    )

    recent_log.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": client_ip, "method": request.method, "path": "/" + path,
        "allowed": decision.allowed, "reason": decision.reason,
    })

    if not decision.allowed:
        return Response(f"Blocked by WAF: {decision.reason}", status=403)

    resp = requests.request(
        method=request.method,
        url=f"{BACKEND}/{path}",
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=raw_body,
        params=request.args,
        allow_redirects=False,
        timeout=5,
    )
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, status=resp.status_code, headers=headers)


if __name__ == "__main__":
    app.run(port=8080, debug=False)
