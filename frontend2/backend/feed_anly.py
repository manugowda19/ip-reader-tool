import redis
import pandas as pd
from collections import defaultdict

# -----------------------------
# Redis Connection
# -----------------------------
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# -----------------------------
# Collect Feed Data From Redis
# -----------------------------
feed_ips = defaultdict(set)

print("Scanning Redis for threat data...")

cursor = 0

while True:

    cursor, keys = r.scan(cursor, match="ip:*", count=1000)

    for key in keys:

        data = r.hgetall(key)

        ip = key.split(":")[1]

        sources = data.get("sources", "")

        for src in sources.split(","):

            if src:
                feed_ips[src].add(ip)

    if cursor == 0:
        break

print("Feeds discovered:", list(feed_ips.keys()))

# -----------------------------
# Build Overlap Matrix
# -----------------------------
feeds = list(feed_ips.keys())

matrix = []

for feed_a in feeds:

    row = []

    for feed_b in feeds:

        overlap = len(feed_ips[feed_a].intersection(feed_ips[feed_b]))

        row.append(overlap)

    matrix.append(row)

# -----------------------------
# Display Matrix
# -----------------------------
df = pd.DataFrame(matrix, index=feeds, columns=feeds)

print("\nFeed Overlap Analysis Matrix\n")

print(df)
