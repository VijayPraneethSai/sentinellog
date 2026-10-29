import sys
import pandas as pd

path = sys.argv[1]
df = pd.read_csv(path)
df["ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True)
fails = df[df["event"] == "login_failed"].sort_values("ts")

for window in (60, 120, 300):
    for thresh in (3, 4, 5, 6):
        n_incidents = 0
        for ip, g in fails.groupby("src_ip"):
            times = g["ts"].sort_values().tolist()
            i = 0
            fired = False
            for j in range(len(times)):
                while times[j] - times[i] > pd.Timedelta(seconds=window):
                    i += 1
                if (j - i + 1) >= thresh:
                    fired = True
                    break
            if fired:
                n_incidents += 1
        print(f"window={window:>4}s thresh={thresh}  -> {n_incidents} source IPs flagged "
              f"(of {fails['src_ip'].nunique()} total)")
