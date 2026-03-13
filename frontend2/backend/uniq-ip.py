import redis
import pandas as pd
from collections import defaultdict

# -----------------------------
# Redis Connection
# -----------------------------
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# -----------------------------
# Extract Feed Data From Redis
# -----------------------------
feed_ips = defaultdict(set)

print("Scanning Redis...")

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

feeds = list(feed_ips.keys())

print("\nFeeds discovered:")
print(feeds)

# -----------------------------
# Feed Overlap Matrix
# -----------------------------
overlap_matrix = []

for feed_a in feeds:

    row = []

    for feed_b in feeds:

        overlap = len(feed_ips[feed_a].intersection(feed_ips[feed_b]))

        row.append(overlap)

    overlap_matrix.append(row)

overlap_df = pd.DataFrame(overlap_matrix, index=feeds, columns=feeds)

print("\nFeed Overlap Matrix\n")
print(overlap_df)

# -----------------------------
# Jaccard Similarity Matrix
# -----------------------------
similarity_matrix = []

for feed_a in feeds:

    row = []

    for feed_b in feeds:

        intersection = len(feed_ips[feed_a].intersection(feed_ips[feed_b]))
        union = len(feed_ips[feed_a].union(feed_ips[feed_b]))

        if union == 0:
            similarity = 0
        else:
            similarity = intersection / union

        row.append(round(similarity, 3))

    similarity_matrix.append(row)

similarity_df = pd.DataFrame(similarity_matrix, index=feeds, columns=feeds)

print("\nFeed Similarity Matrix (Jaccard)\n")
print(similarity_df)

# -----------------------------
# Unique IP Contribution
# -----------------------------
print("\nUnique IP Contribution per Feed\n")

unique_counts = {}

for feed in feeds:

    other_feeds = set().union(*(feed_ips[f] for f in feeds if f != feed))

    unique_ips = feed_ips[feed] - other_feeds

    unique_counts[feed] = len(unique_ips)

unique_df = pd.DataFrame.from_dict(unique_counts, orient="index", columns=["Unique_IPs"])

print(unique_df.sort_values(by="Unique_IPs", ascending=False))
