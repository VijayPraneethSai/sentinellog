"""
Per-user baselines used by the detectors.

Each user gets:
  - an hour-of-day login distribution (for the off-baseline-time detector)
  - a "home" location, inferred as their most frequent (lat, lon) in a
    trailing training window (for the impossible-travel detector)

Baselines are built from a trailing window *ending before* the event under
test, so a detector never uses future data to judge a past event (avoids
leakage, and mirrors how a real system would only know what happened so far).
"""
import numpy as np
import pandas as pd


class UserBaseline:
    def __init__(self, hour_counts: np.ndarray, home_lat: float, home_lon: float, n_events: int):
        self.hour_counts = hour_counts  # length-24 histogram
        self.home_lat = home_lat
        self.home_lon = home_lon
        self.n_events = n_events

    def hour_rarity(self, hour: int, min_baseline_events: int = 8) -> float:
        """Fraction of this user's historical logins that happen at `hour`.
        A histogram-based z-score is the wrong tool here: most hours in a
        login histogram are near zero for every user (logins cluster in a
        narrow work window), so z-scores over the raw counts barely move.
        Fraction-of-total is the direct, interpretable measure of "how rare
        is this hour for this specific person." Low n_events -> treated as
        unknown (rarity=1.0, i.e. not flagged) rather than penalizing a
        user we barely have history for."""
        if self.n_events < min_baseline_events:
            return 1.0
        total = self.hour_counts.sum()
        if total < 1e-6:
            return 1.0
        return float(self.hour_counts[hour]) / float(total)


def build_baselines(df: pd.DataFrame, as_of_ts) -> dict:
    """Build one UserBaseline per user using only events strictly before
    as_of_ts, and only successful logins (failed logins shouldn't anchor
    'where this user normally logs in from')."""
    train = df[(df["ts"] < as_of_ts) & (df["event"] == "login_success")]
    baselines = {}
    for user, g in train.groupby("user"):
        hours = g["ts"].dt.hour.values
        hist = np.bincount(hours, minlength=24).astype(float)
        home_lat = g["lat"].dropna().mode()
        home_lon = g["lon"].dropna().mode()
        baselines[user] = UserBaseline(
            hour_counts=hist,
            home_lat=float(home_lat.iloc[0]) if len(home_lat) else np.nan,
            home_lon=float(home_lon.iloc[0]) if len(home_lon) else np.nan,
            n_events=len(g),
        )
    return baselines
