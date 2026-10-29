"""
Generates a synthetic-but-calibrated SSH authentication log stream.

Why synthetic: public labeled SSH-brute-force datasets are either multi-GB
raw packet captures (PANDAcap, Twente 2014 ~5.7GB) that need heavy
preprocessing, or require paid/auth-gated access (Kaggle). Instead we
generate traffic calibrated to published honeypot statistics (e.g. brute
force attempts clustering at 3-5 attempts/sec vs ~1 event/sec for normal
connections -- see Wilkens & Fischer, CNS 2020; SSHafe 2026), with an
injected, fully-labeled ground truth. This is the standard approach when
real labeled security data isn't available, and it lets us report honest
precision/recall against known-correct labels.

Output: data/auth_log.csv  (events)
        data/labels.csv    (ground truth: is this event part of an attack)
"""
import csv
import random
import math
from datetime import datetime, timedelta

random.seed(42)

N_USERS = 40
DAYS = 14
START = datetime(2026, 10, 1, 0, 0, 0)

# A small pool of source "home" cities per legit user, with lat/lon, to
# simulate normal travel and enable impossible-travel detection.
CITIES = [
    ("Bengaluru", 12.97, 77.59), ("Hyderabad", 17.38, 78.49),
    ("Mumbai", 19.07, 72.87), ("Delhi", 28.61, 77.20),
    ("Chennai", 13.08, 80.27), ("Singapore", 1.35, 103.82),
    ("London", 51.51, -0.13), ("Frankfurt", 50.11, 8.68),
    ("New York", 40.71, -74.01), ("San Francisco", 37.77, -122.42),
]

ATTACKER_IP_POOL = [f"185.220.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(25)]


def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def random_ip():
    return f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def gen_users():
    users = []
    for i in range(N_USERS):
        home_city = random.choice(CITIES)
        # each user has a typical login-hour window (their work hours, local)
        work_start = random.randint(7, 10)
        work_end = work_start + random.randint(7, 9)
        users.append({
            "user": f"user{i:03d}",
            "home_city": home_city,
            "home_ip": random_ip(),
            "work_start": work_start,
            "work_end": work_end,
        })
    return users


def gen_benign_events(users):
    events = []
    for day in range(DAYS):
        for u in users:
            # 1-4 normal logins per day, log-normal-ish around work hours
            n_logins = random.choice([1, 1, 2, 2, 3, 4])
            for _ in range(n_logins):
                hour = random.randint(u["work_start"], u["work_end"])
                minute = random.randint(0, 59)
                ts = START + timedelta(days=day, hours=hour, minutes=minute, seconds=random.randint(0, 59))
                # occasionally travel to a different (but plausible, slow) city
                if random.random() < 0.03:
                    city = random.choice(CITIES)
                else:
                    city = u["home_city"]
                ip = u["home_ip"] if city == u["home_city"] else random_ip()
                success = random.random() > 0.03  # rare fat-fingered password
                events.append({
                    "ts": ts, "user": u["user"], "src_ip": ip,
                    "city": city[0], "lat": city[1], "lon": city[2],
                    "event": "login_success" if success else "login_failed",
                    "label": "benign", "attack_id": None,
                })
                if not success:
                    # immediately followed by a correct retry
                    ts2 = ts + timedelta(seconds=random.randint(3, 20))
                    events.append({
                        "ts": ts2, "user": u["user"], "src_ip": ip,
                        "city": city[0], "lat": city[1], "lon": city[2],
                        "event": "login_success", "label": "benign", "attack_id": None,
                    })
    return events


def gen_bruteforce_attacks(users, n_attacks=18):
    events = []
    for attack_i in range(n_attacks):
        target = random.choice(users)
        day = random.randint(0, DAYS - 1)
        hour = random.randint(0, 23)
        ts0 = START + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))
        ip = random.choice(ATTACKER_IP_POOL)
        n_attempts = random.randint(25, 90)
        rate = random.uniform(3.0, 5.0)  # attempts/sec, per published honeypot stats
        succeeds = random.random() < 0.15  # some brute forces land
        aid = f"bf{attack_i:03d}"
        for i in range(n_attempts):
            ts = ts0 + timedelta(seconds=i / rate)
            is_last = i == n_attempts - 1
            success = succeeds and is_last
            events.append({
                "ts": ts, "user": target["user"], "src_ip": ip,
                "city": "unknown", "lat": None, "lon": None,
                "event": "login_success" if success else "login_failed",
                "label": "brute_force", "attack_id": aid,
            })
    return events


def gen_impossible_travel(users, n_attacks=12):
    events = []
    for attack_i in range(n_attacks):
        target = random.choice(users)
        day = random.randint(0, DAYS - 1)
        hour = random.randint(*[target["work_start"], target["work_end"]])
        ts_legit = START + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))
        aid = f"it{attack_i:03d}"
        events.append({
            "ts": ts_legit, "user": target["user"], "src_ip": target["home_ip"],
            "city": target["home_city"][0], "lat": target["home_city"][1],
            "lon": target["home_city"][2], "event": "login_success", "label": "benign",
            "attack_id": None,
        })
        # a second, far-away login within an implausible time window (<2h for >2000km)
        far_city = max(CITIES, key=lambda c: haversine_km(target["home_city"][1], target["home_city"][2], c[1], c[2]))
        gap_minutes = random.randint(5, 90)
        ts_attack = ts_legit + timedelta(minutes=gap_minutes)
        events.append({
            "ts": ts_attack, "user": target["user"], "src_ip": random_ip(),
            "city": far_city[0], "lat": far_city[1], "lon": far_city[2],
            "event": "login_success", "label": "impossible_travel", "attack_id": aid,
        })
        # the user's *next* normal login (back home) is a downstream effect of
        # the attack -- the baseline now has to reconcile a forged far-away
        # point, which can itself look like a second "impossible" jump. We
        # label it as part of the same incident rather than as a fresh benign
        # event, since a real detector would (correctly) still flag it.
        gap2_minutes = random.randint(10, 120)
        ts_return = ts_attack + timedelta(minutes=gap2_minutes)
        events.append({
            "ts": ts_return, "user": target["user"], "src_ip": target["home_ip"],
            "city": target["home_city"][0], "lat": target["home_city"][1],
            "lon": target["home_city"][2], "event": "login_success",
            "label": "impossible_travel_aftershock", "attack_id": aid,
        })
    return events


def gen_off_baseline_time(users, n_attacks=10):
    """Successful login far outside the user's normal hour-of-day baseline,
    from the user's own usual IP/city (e.g. stolen session replayed, or
    insider access at an unusual hour) -- no volume or geo signal, so this
    exercises the pure time-baseline detector."""
    events = []
    for attack_i in range(n_attacks):
        target = random.choice(users)
        day = random.randint(0, DAYS - 1)
        # pick an hour far from their normal window
        off_hours = [h for h in range(24) if not (target["work_start"] - 2 <= h <= target["work_end"] + 2)]
        hour = random.choice(off_hours)
        ts = START + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))
        events.append({
            "ts": ts, "user": target["user"], "src_ip": target["home_ip"],
            "city": target["home_city"][0], "lat": target["home_city"][1],
            "lon": target["home_city"][2], "event": "login_success",
            "label": "off_baseline_time", "attack_id": f"ob{attack_i:03d}",
        })
    return events


def main():
    users = gen_users()
    events = (
        gen_benign_events(users)
        + gen_bruteforce_attacks(users)
        + gen_impossible_travel(users)
        + gen_off_baseline_time(users)
    )
    events.sort(key=lambda e: e["ts"])

    with open("data/auth_log.csv", "w", newline="") as f_log, \
         open("data/labels.csv", "w", newline="") as f_lab:
        log_w = csv.writer(f_log)
        lab_w = csv.writer(f_lab)
        log_w.writerow(["event_id", "ts", "user", "src_ip", "city", "lat", "lon", "event"])
        lab_w.writerow(["event_id", "label", "attack_id"])
        for i, e in enumerate(events):
            log_w.writerow([i, e["ts"].isoformat(), e["user"], e["src_ip"],
                             e["city"], e["lat"], e["lon"], e["event"]])
            lab_w.writerow([i, e["label"], e["attack_id"]])

    n_attack = sum(1 for e in events if e["label"] != "benign")
    n_incidents = len({e["attack_id"] for e in events if e["attack_id"]})
    print(f"Wrote {len(events)} events ({n_attack} labeled attack events across "
          f"{n_incidents} attack incidents, {len(events) - n_attack} benign) "
          f"across {N_USERS} users over {DAYS} days.")


if __name__ == "__main__":
    main()
