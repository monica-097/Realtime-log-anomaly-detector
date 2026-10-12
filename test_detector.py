"""Unit tests for detector.py. Run with: pytest"""
from detector import Detector, parse_line


def entry(ip="198.51.100.44", t=0, status=401, path="/login"):
    return {"ip": ip, "timestamp": f"t{t}", "epoch": float(t),
            "method": "POST", "path": path, "status": status, "size": "128"}


def run(detector, entries):
    alerts = []
    for e in entries:
        alerts.extend(detector.analyze(e))
    return alerts


def test_parse_valid_line():
    line = '203.0.113.20 - - [12/Oct/2026:10:00:00 +0000] "GET /index HTTP/1.1" 200 512'
    e = parse_line(line)
    assert e["ip"] == "203.0.113.20"
    assert e["path"] == "/index"
    assert e["status"] == 200


def test_parse_invalid_line_returns_none():
    assert parse_line("this is not a log line") is None


def test_brute_force_triggers_at_threshold():
    alerts = run(Detector(), [entry(t=i) for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert "brute-force" in alerts[0]["alert_type"]


def test_below_threshold_no_alert():
    assert run(Detector(), [entry(t=i) for i in range(4)]) == []


def test_failures_outside_window_do_not_count():
    # 5 failures spread 100s apart never fit inside a 60s window
    assert run(Detector(), [entry(t=i * 100) for i in range(5)]) == []


def test_path_scanning_detected():
    alerts = run(Detector(), [entry(t=i, status=404, path=f"/x{i}") for i in range(10)])
    assert any(a["alert_type"] == "Possible path scanning" for a in alerts)


def test_sensitive_path_detected():
    alerts = run(Detector(), [entry(status=200, path="/.env")])
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Request for a sensitive path"


def test_cooldown_suppresses_duplicate_alerts():
    d = Detector(cooldown=60)
    alerts = run(d, [entry(t=i) for i in range(8)])  # keeps exceeding threshold
    assert len(alerts) == 1


def test_different_ips_tracked_independently():
    entries = [entry(ip="1.1.1.1", t=i) for i in range(3)] + \
              [entry(ip="2.2.2.2", t=i) for i in range(3)]
    assert run(Detector(), entries) == []