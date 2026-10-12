#!/usr/bin/env python3
"""Real-time web access-log anomaly detector. Python standard library only."""
import argparse
import csv
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

# Common/combined-style access log, e.g. 192.0.2.10 - - [12/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 123
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
SENSITIVE_PATHS = ("/.env", "/wp-admin", "/wp-login", "/admin", "/phpmyadmin", "/.git", "/config")

class Detector:
    def __init__(self, window=60, failed_threshold=5, scan_threshold=10, cooldown=60):
        self.window = window
        self.failed_threshold = failed_threshold
        self.scan_threshold = scan_threshold
        self.cooldown = cooldown
        self.failed = defaultdict(deque)
        self.not_found = defaultdict(deque)
        self.last_alert = {}

    def analyze(self, entry):
        now = entry["epoch"]
        ip, status, path = entry["ip"], entry["status"], entry["path"].lower()
        alerts = []
        if status in (401, 403):
            q = self.failed[ip]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.failed_threshold:
                alerts.append(("HIGH", "Possible brute-force / repeated authentication failures",
                               f"{len(q)} HTTP {status} responses from {ip} in {self.window}s"))
        if status == 404:
            q = self.not_found[ip]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.scan_threshold:
                alerts.append(("MEDIUM", "Possible path scanning", f"{len(q)} HTTP 404 responses from {ip} in {self.window}s"))
        if any(path == p or path.startswith(p + "/") or path.startswith(p + "?") for p in SENSITIVE_PATHS):
            alerts.append(("MEDIUM", "Request for a sensitive path", f"{ip} requested {entry['path']} (HTTP {status})"))
        # Deduplicate each rule per IP/path for a cooldown period.
        emitted = []
        for severity, kind, detail in alerts:
            key = (ip, kind, entry["path"] if kind == "Request for a sensitive path" else "")
            if now - self.last_alert.get(key, float("-inf")) >= self.cooldown:
                self.last_alert[key] = now
                emitted.append({"timestamp": entry["timestamp"], "severity": severity,
                                "source_ip": ip, "alert_type": kind, "details": detail,
                                "path": entry["path"], "status": status})
        return emitted

def parse_line(line):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        parsed = datetime.strptime(d["date"], "%d/%b/%Y:%H:%M:%S %z")
        epoch = parsed.timestamp()
    except ValueError:
        epoch = time.time()
    return {"ip": d["ip"], "timestamp": d["date"], "epoch": epoch,
            "method": d["method"], "path": d["path"], "status": int(d["status"]),
            "size": d["size"]}

def append_alerts(alerts, output):
    if not alerts:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    exists = output.exists() and output.stat().st_size > 0
    with output.open("a", newline="", encoding="utf-8") as f:
        fields = ["timestamp", "severity", "source_ip", "alert_type", "details", "path", "status"]
        writer = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerows(alerts)
    for a in alerts:
        print(f"\n[{a['severity']}] {a['alert_type']}\n  Time: {a['timestamp']}\n  IP: {a['source_ip']}\n  {a['details']}\n")

def follow_file(path, detector, output, poll=0.5, from_end=False):
    print(f"[*] Watching {path} (Ctrl+C to stop). Alerts -> {output}")
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if from_end:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                continue
            entry = parse_line(line)
            if entry is None:
                print(f"[!] Skipped unrecognized log line: {line.rstrip()[:160]}", file=sys.stderr)
                continue
            append_alerts(detector.analyze(entry), output)

def analyze_existing(path, detector, output):
    count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = parse_line(line)
        if entry:
            count += 1
            append_alerts(detector.analyze(entry), output)
    print(f"[*] Analysed {count} valid log entries. Alert file: {output}")

def main():
    parser = argparse.ArgumentParser(description="Monitor web access logs for suspicious patterns")
    parser.add_argument("logfile", nargs="?", default="sample_access.log", help="path to an access log")
    parser.add_argument("--follow", action="store_true", help="watch for newly appended log lines")
    parser.add_argument("--from-end", action="store_true", help="with --follow, ignore existing lines")
    parser.add_argument("--alerts", default="alerts.csv", help="CSV alert output path (default: alerts.csv)")
    parser.add_argument("--window", type=int, default=60, help="detection time window in seconds")
    parser.add_argument("--failed-threshold", type=int, default=5, help="401/403 count before brute-force alert")
    parser.add_argument("--scan-threshold", type=int, default=10, help="404 count before scanning alert")
    parser.add_argument("--cooldown", type=int, default=60, help="seconds before repeating the same alert")
    args = parser.parse_args()
    logfile, output = Path(args.logfile), Path(args.alerts)
    if not logfile.exists():
        parser.error(f"log file not found: {logfile}")
    detector = Detector(args.window, args.failed_threshold, args.scan_threshold, args.cooldown)
    try:
        if args.follow:
            follow_file(logfile, detector, output, from_end=args.from_end)
        else:
            analyze_existing(logfile, detector, output)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")

if __name__ == "__main__":
    main()
