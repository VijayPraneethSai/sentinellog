"""
Adapter: converts a Cowrie SSH/Telnet honeypot JSON-lines log into
SentinelLog's event schema, so the same pipeline that runs on the
synthetic calibration data can run unmodified on real-world attack
traffic.

Cowrie (https://github.com/cowrie/cowrie) is a widely used SSH/Telnet
honeypot; its JSON event log is a de facto standard format for this kind
of data. This adapter only reads cowrie.login.failed / cowrie.login.success
events -- it ignores command execution, file transfer, etc., since those
are out of scope for an auth-log triage tool.

Cowrie captures no geolocation, so `city`/`lat`/`lon` are left empty. That
means the impossible-travel and off-baseline-time detectors will not fire
on Cowrie data (not enough signal), by design -- only the brute-force /
credential-stuffing detector is exercised here. See
docs/real_data_validation.md for what that validates and what it doesn't.
"""
import csv
import json
import sys


def _read_login_rows(cowrie_jsonl_path: str) -> list[dict]:
    rows = []
    with open(cowrie_jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            eid = e.get("eventid")
            if eid == "cowrie.login.failed":
                event = "login_failed"
            elif eid == "cowrie.login.success":
                event = "login_success"
            else:
                continue
            rows.append({
                "ts": e.get("timestamp"),
                "user": e.get("username", "unknown"),
                "src_ip": e.get("src_ip", "unknown"),
                "city": "", "lat": "", "lon": "",
                "event": event,
            })
    return rows


def convert(cowrie_jsonl_path: str, out_csv_path: str) -> int:
    rows = _read_login_rows(cowrie_jsonl_path)
    return _write_rows(rows, out_csv_path)


def convert_many(cowrie_jsonl_paths: list[str], out_csv_path: str) -> int:
    """Combine several daily Cowrie log files into one chronologically
    sorted event stream, so a multi-day real-world validation can be run
    the same way the synthetic multi-day dataset is."""
    rows = []
    for p in cowrie_jsonl_paths:
        rows.extend(_read_login_rows(p))
    return _write_rows(rows, out_csv_path)


def _write_rows(rows: list[dict], out_csv_path: str) -> int:
    rows.sort(key=lambda r: r["ts"])
    with open(out_csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "ts", "user", "src_ip", "city", "lat", "lon", "event"])
        for i, r in enumerate(rows):
            w.writerow([i, r["ts"], r["user"], r["src_ip"], r["city"], r["lat"], r["lon"], r["event"]])
    return len(rows)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python -m sentinellog.adapters.cowrie <cowrie.json> [more...] <out.csv>")
        sys.exit(1)
    *inputs, output = sys.argv[1:]
    if len(inputs) == 1:
        n = convert(inputs[0], output)
    else:
        n = convert_many(inputs, output)
    print(f"wrote {n} login events from {len(inputs)} file(s) to {output}")
