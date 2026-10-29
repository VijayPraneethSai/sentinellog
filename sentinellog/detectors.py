"""
Three independent detectors, each producing Alert objects with a score and
a human-readable reason. Keeping them independent (rather than one fused
model) means each alert is individually explainable -- you can say exactly
why it fired, which matters more than raw accuracy for a triage tool.
"""
import math
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

from .baseline import UserBaseline

EARTH_R_KM = 6371.0


def haversine_km(lat1, lon1, lat2, lon2):
    if any(pd.isna(v) for v in (lat1, lon1, lat2, lon2)):
        return None
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_R_KM * math.asin(math.sqrt(a))


@dataclass
class Alert:
    event_id: int
    ts: str
    user: str
    detector: str
    score: float
    reason: str
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------
# 1. Brute-force / credential-stuffing burst detector
# ---------------------------------------------------------------------
def detect_bruteforce(df: pd.DataFrame, window_seconds: int = 60,
                       fail_threshold: int = 6) -> list[Alert]:
    """Flags (user or src_ip, window) pairs with an unusually dense burst
    of failed logins. Two independent axes are checked -- per-target-user
    (classic brute force) and per-source-IP across multiple users
    (credential stuffing) -- since a stuffing attack spreads load across
    accounts and wouldn't trip a per-user-only counter.
    """
    alerts = []
    fails = df[df["event"] == "login_failed"].sort_values("ts")

    for key_col, label in (("user", "brute_force"), ("src_ip", "credential_stuffing")):
        for key, g in fails.groupby(key_col):
            g = g.sort_values("ts")
            times = g["ts"].values
            ids = g["event_id"].values
            n = len(times)
            i = 0
            last_alert_end = None  # one alert per burst, not one per event
            for j in range(n):
                while times[j] - times[i] > pd.Timedelta(seconds=window_seconds):
                    i += 1
                count = j - i + 1
                if count >= fail_threshold:
                    if last_alert_end is not None and times[j] - last_alert_end <= pd.Timedelta(seconds=window_seconds):
                        continue  # still inside the burst we already alerted on
                    rate = count / window_seconds
                    score = min(1.0, count / (fail_threshold * 4))
                    alerts.append(Alert(
                        event_id=int(ids[j]),
                        ts=str(g["ts"].iloc[j]),
                        user=g["user"].iloc[j],
                        detector=label,
                        score=round(score, 3),
                        reason=(f"{count} failed logins in {window_seconds}s "
                                f"({'target user' if key_col=='user' else 'source IP'}={key}, "
                                f"~{rate:.1f}/s) -- incident start"),
                        evidence={"window_s": window_seconds, "fail_count": count,
                                  key_col: str(key)},
                    ))
                    last_alert_end = times[j]
    return alerts


# ---------------------------------------------------------------------
# 2. Impossible travel detector
# ---------------------------------------------------------------------
def detect_impossible_travel(df: pd.DataFrame, max_speed_kmh: float = 900.0) -> list[Alert]:
    """Flags a successful login whose implied travel speed from the user's
    immediately preceding successful login exceeds max_speed_kmh (commercial
    flight speed -- a generous bound chosen to minimize false positives from
    real travel/VPNs, since this is a triage tool, not an auto-block)."""
    alerts = []
    logins = df[df["event"] == "login_success"].sort_values("ts")
    for user, g in logins.groupby("user"):
        g = g.sort_values("ts").reset_index(drop=True)
        for i in range(1, len(g)):
            prev, cur = g.iloc[i - 1], g.iloc[i]
            dist = haversine_km(prev["lat"], prev["lon"], cur["lat"], cur["lon"])
            if dist is None:
                continue
            hours = (cur["ts"] - prev["ts"]).total_seconds() / 3600.0
            if hours <= 0:
                continue
            speed = dist / hours
            if speed > max_speed_kmh and dist > 300:
                score = min(1.0, speed / (max_speed_kmh * 5))
                alerts.append(Alert(
                    event_id=int(cur["event_id"]), ts=str(cur["ts"]), user=user,
                    detector="impossible_travel", score=round(score, 3),
                    reason=(f"{dist:.0f} km from previous login "
                            f"({prev['city']}->{cur['city']}) in {hours:.2f}h "
                            f"=> implied {speed:.0f} km/h"),
                    evidence={"distance_km": round(dist, 1), "hours": round(hours, 3),
                              "implied_kmh": round(speed, 1),
                              "from_city": prev["city"], "to_city": cur["city"]},
                ))
    return alerts


# ---------------------------------------------------------------------
# 3. Off-baseline login-time detector
# ---------------------------------------------------------------------
def detect_off_baseline_time(df: pd.DataFrame, baselines: dict[str, UserBaseline],
                              rarity_threshold: float = 0.03) -> list[Alert]:
    """Flags a successful login at an hour-of-day this specific user almost
    never uses (rarity_threshold = fraction of their own history). Catches
    cases with no volume or geo signal at all (e.g. a replayed/stolen
    session used from the user's own usual network, at a time they never
    normally log in)."""
    alerts = []
    logins = df[df["event"] == "login_success"].sort_values("ts")
    for _, row in logins.iterrows():
        bl = baselines.get(row["user"])
        if bl is None:
            continue
        hour = row["ts"].hour
        rarity = bl.hour_rarity(hour)
        if rarity < rarity_threshold:
            score = min(1.0, 1.0 - rarity / rarity_threshold)
            alerts.append(Alert(
                event_id=int(row["event_id"]), ts=str(row["ts"]), user=row["user"],
                detector="off_baseline_time", score=round(score, 3),
                reason=(f"login at hour={hour}:00, which is {rarity*100:.1f}% of this "
                        f"user's own {bl.n_events}-login history"),
                evidence={"hour": int(hour), "hour_fraction": round(rarity, 4),
                          "baseline_events": bl.n_events},
            ))
    return alerts
