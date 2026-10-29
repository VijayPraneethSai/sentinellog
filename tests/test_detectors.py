import pandas as pd
import pytest

from sentinellog.baseline import build_baselines
from sentinellog.detectors import detect_bruteforce, detect_impossible_travel, detect_off_baseline_time


def _df(rows):
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"])
    df["event_id"] = range(len(df))
    return df


def test_bruteforce_flags_dense_failure_burst():
    base = pd.Timestamp("2026-01-01 10:00:00")
    rows = [{"ts": base + pd.Timedelta(seconds=i * 0.3), "user": "alice",
              "src_ip": "1.2.3.4", "event": "login_failed",
              "city": None, "lat": None, "lon": None} for i in range(10)]
    df = _df(rows)
    alerts = detect_bruteforce(df, window_seconds=60, fail_threshold=6)
    # a single-attacker-vs-single-target burst trips both axes (per-target-user
    # and per-source-IP) -- the pipeline later merges these to one alert per
    # event_id (see pipeline.merge_alerts); at the raw-detector level we expect
    # one incident-start alert on each axis.
    assert len(alerts) == 2
    assert {a.detector for a in alerts} == {"brute_force", "credential_stuffing"}


def test_bruteforce_ignores_sparse_failures():
    base = pd.Timestamp("2026-01-01 10:00:00")
    rows = [{"ts": base + pd.Timedelta(minutes=i * 30), "user": "alice",
              "src_ip": "1.2.3.4", "event": "login_failed",
              "city": None, "lat": None, "lon": None} for i in range(5)]
    df = _df(rows)
    alerts = detect_bruteforce(df, window_seconds=60, fail_threshold=6)
    assert len(alerts) == 0


def test_bruteforce_dedupes_to_one_alert_per_incident():
    base = pd.Timestamp("2026-01-01 10:00:00")
    rows = [{"ts": base + pd.Timedelta(seconds=i * 0.2), "user": "bob",
              "src_ip": "9.9.9.9", "event": "login_failed",
              "city": None, "lat": None, "lon": None} for i in range(40)]
    df = _df(rows)
    alerts = detect_bruteforce(df, window_seconds=60, fail_threshold=6)
    # one incident-start alert per axis (user, src_ip), not one per failed login
    assert len(alerts) == 2


def test_impossible_travel_flags_fast_jump():
    rows = [
        {"ts": "2026-01-01 10:00:00", "user": "alice", "src_ip": "1.1.1.1",
         "event": "login_success", "city": "Hyderabad", "lat": 17.38, "lon": 78.49},
        {"ts": "2026-01-01 10:30:00", "user": "alice", "src_ip": "2.2.2.2",
         "event": "login_success", "city": "New York", "lat": 40.71, "lon": -74.01},
    ]
    df = _df(rows)
    alerts = detect_impossible_travel(df, max_speed_kmh=900)
    assert len(alerts) == 1
    assert alerts[0].evidence["implied_kmh"] > 900


def test_impossible_travel_allows_plausible_flight():
    rows = [
        {"ts": "2026-01-01 10:00:00", "user": "alice", "src_ip": "1.1.1.1",
         "event": "login_success", "city": "Hyderabad", "lat": 17.38, "lon": 78.49},
        {"ts": "2026-01-01 22:00:00", "user": "alice", "src_ip": "2.2.2.2",
         "event": "login_success", "city": "London", "lat": 51.51, "lon": -0.13},
    ]
    df = _df(rows)
    alerts = detect_impossible_travel(df, max_speed_kmh=900)
    assert len(alerts) == 0


def test_off_baseline_time_needs_enough_history():
    # Only 3 historical logins -- too little to trust a baseline from.
    rows = [{"ts": f"2026-01-0{d} 09:00:00", "user": "alice", "src_ip": "1.1.1.1",
              "event": "login_success", "city": "X", "lat": 1.0, "lon": 1.0} for d in range(1, 4)]
    rows.append({"ts": "2026-01-10 03:00:00", "user": "alice", "src_ip": "1.1.1.1",
                  "event": "login_success", "city": "X", "lat": 1.0, "lon": 1.0})
    df = _df(rows)
    baselines = build_baselines(df, as_of_ts=pd.Timestamp("2026-01-10"))
    alerts = detect_off_baseline_time(df[df["ts"] >= "2026-01-10"], baselines)
    assert len(alerts) == 0  # alice has < 8 historical events -> not flagged


def test_off_baseline_time_flags_rare_hour_with_enough_history():
    rows = [{"ts": f"2026-01-{d:02d} 09:00:00", "user": "alice", "src_ip": "1.1.1.1",
              "event": "login_success", "city": "X", "lat": 1.0, "lon": 1.0} for d in range(1, 11)]
    rows.append({"ts": "2026-01-15 03:00:00", "user": "alice", "src_ip": "1.1.1.1",
                  "event": "login_success", "city": "X", "lat": 1.0, "lon": 1.0})
    df = _df(rows)
    baselines = build_baselines(df, as_of_ts=pd.Timestamp("2026-01-15"))
    alerts = detect_off_baseline_time(df[df["ts"] >= "2026-01-15"], baselines, rarity_threshold=0.03)
    assert len(alerts) == 1
    assert alerts[0].evidence["hour"] == 3
