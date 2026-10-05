from waf_core import WAF


def test_allow_normal_request():
    waf = WAF()
    d = waf.inspect("203.0.113.5", "GET", "/search", query_string="q=apple")
    assert d.allowed


def test_block_sql_injection():
    waf = WAF()
    d = waf.inspect("203.0.113.5", "GET", "/search", query_string="q=apple' OR '1'='1")
    assert not d.allowed
    assert "sql_injection" in d.reason


def test_block_xss():
    waf = WAF()
    d = waf.inspect("203.0.113.5", "GET", "/echo", query_string="msg=<script>alert(1)</script>")
    assert not d.allowed
    assert "xss" in d.reason


def test_block_path_traversal():
    waf = WAF()
    d = waf.inspect("203.0.113.5", "GET", "/files", query_string="path=../../etc/passwd")
    assert not d.allowed
    assert "path_traversal" in d.reason


def test_rate_limit():
    waf = WAF(requests_per_window=3, window_seconds=5.0)
    ip = "203.0.113.9"
    results = [waf.inspect(ip, "GET", "/").allowed for _ in range(6)]
    assert False in results


def test_block_list():
    waf = WAF()
    waf.ip_list.block("203.0.113.50")
    d = waf.inspect("203.0.113.50", "GET", "/")
    assert not d.allowed
    assert d.reason == "IP on block list"


def test_allow_override_bypasses_rate_limit():
    waf = WAF(requests_per_window=2, window_seconds=5.0)
    ip = "203.0.113.20"
    waf.ip_list.allow_always(ip)
    results = [waf.inspect(ip, "GET", "/").allowed for _ in range(10)]
    assert all(results)
