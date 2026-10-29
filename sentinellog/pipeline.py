"""Glue: load logs, build trailing baselines, run all detectors, merge
alerts per event (an event can be flagged by more than one detector --
keep the max score and combine reasons), rank by score."""
import pandas as pd

from .baseline import build_baselines
from .config import SentinelLogConfig
from .detectors import (Alert, detect_bruteforce, detect_impossible_travel,
                         detect_off_baseline_time)


def load_events(log_path: str) -> pd.DataFrame:
    df = pd.read_csv(log_path)
    ts = pd.to_datetime(df["ts"], format="ISO8601")
    # Normalize to tz-naive: the synthetic generator emits naive local
    # timestamps, while real-world sources (e.g. Cowrie, which logs UTC
    # with a 'Z' suffix) are tz-aware. Mixing the two breaks comparisons
    # throughout the pipeline, so every source is brought to the same
    # (naive, UTC-equivalent) representation at load time.
    if ts.dt.tz is not None:
        ts = ts.dt.tz_convert("UTC").dt.tz_localize(None)
    df["ts"] = ts
    return df


def run_pipeline(df: pd.DataFrame, config: SentinelLogConfig | None = None) -> list[Alert]:
    cfg = config or SentinelLogConfig.load()
    all_alerts: list[Alert] = []

    all_alerts += detect_bruteforce(
        df, window_seconds=cfg.bruteforce.window_seconds,
        fail_threshold=cfg.bruteforce.fail_threshold,
    )
    all_alerts += detect_impossible_travel(
        df, max_speed_kmh=cfg.impossible_travel.max_speed_kmh,
    )

    # Off-baseline-time needs a per-event trailing baseline (built from
    # data strictly before that event) so we don't leak the future into
    # a user's "normal" profile. Rebuilding per-day keeps this cheap.
    df_sorted = df.sort_values("ts")
    df_sorted["day"] = df_sorted["ts"].dt.date
    for day, day_df in df_sorted.groupby("day"):
        as_of = pd.Timestamp(day)
        baselines = build_baselines(df_sorted, as_of_ts=as_of)
        all_alerts += detect_off_baseline_time(
            day_df, baselines,
            rarity_threshold=cfg.off_baseline_time.rarity_threshold,
            min_baseline_events=cfg.off_baseline_time.min_baseline_events,
        )

    return merge_alerts(all_alerts)


def merge_alerts(alerts: list[Alert]) -> list[Alert]:
    by_event: dict[int, Alert] = {}
    for a in alerts:
        existing = by_event.get(a.event_id)
        if existing is None or a.score > existing.score:
            if existing is not None:
                a.reason = existing.reason + " | " + a.reason
                a.detector = existing.detector + "+" + a.detector
            by_event[a.event_id] = a
    return sorted(by_event.values(), key=lambda a: -a.score)
