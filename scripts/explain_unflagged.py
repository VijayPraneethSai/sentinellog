import sys
import pandas as pd

path = sys.argv[1]
df = pd.read_csv(path)
df["ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True)
fails = df[df["event"] == "login_failed"].sort_values("ts")

WINDOW = 120

rows = []
for ip, g in fails.groupby("src_ip"):
    times = g["ts"].sort_values().tolist()
    n = len(times)
    best = 0
    i = 0
    for j in range(n):
        while times[j] - times[i] > pd.Timedelta(seconds=WINDOW):
            i += 1
        best = max(best, j - i + 1)
    rows.append({"src_ip": ip, "total_fails": n, "max_in_120s": best,
                 "span_hours": (times[-1] - times[0]).total_seconds() / 3600})

res = pd.DataFrame(rows).sort_values("total_fails", ascending=False)
with_4plus_total = res[res["total_fails"] >= 4]
print(f"IPs with >=4 total failed logins (ever): {len(with_4plus_total)}")
print(f"of those, IPs that ever reached 4+ fails inside ANY 120s window (i.e. actually burst): "
      f"{(with_4plus_total['max_in_120s'] >= 4).sum()}")
print()
print("the 4+-total IPs that were NOT a burst (spread thin instead of dense):")
print(with_4plus_total[with_4plus_total["max_in_120s"] < 4].to_string(index=False))
