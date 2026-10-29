"""Loads detector thresholds from config.yaml so tuning never requires a
code change -- a config.yaml edit is reviewable in a PR diff the same way
any other config change is, which matters more than it sounds for a
detector whose thresholds get adjusted after real-world false positives."""
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


@dataclass
class BruteforceConfig:
    window_seconds: int = 60
    fail_threshold: int = 6


@dataclass
class ImpossibleTravelConfig:
    max_speed_kmh: float = 900.0


@dataclass
class OffBaselineTimeConfig:
    rarity_threshold: float = 0.03
    min_baseline_events: int = 8


@dataclass
class SentinelLogConfig:
    bruteforce: BruteforceConfig
    impossible_travel: ImpossibleTravelConfig
    off_baseline_time: OffBaselineTimeConfig

    @classmethod
    def default(cls) -> "SentinelLogConfig":
        return cls(BruteforceConfig(), ImpossibleTravelConfig(), OffBaselineTimeConfig())

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "SentinelLogConfig":
        if not Path(path).exists():
            return cls.default()
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return cls(
            bruteforce=BruteforceConfig(**raw.get("bruteforce", {})),
            impossible_travel=ImpossibleTravelConfig(**raw.get("impossible_travel", {})),
            off_baseline_time=OffBaselineTimeConfig(**raw.get("off_baseline_time", {})),
        )
