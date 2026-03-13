"""
IP Threat Feed Ingester
-----------------------
Fetches IP addresses from multiple MISP-listed threat feeds,
calculates an anomaly score based on how many sources list each IP,
and stores everything in Redis using Hash data structures.

Redis Data Structure:
  Key:   ip:<address>        (e.g., ip:1.2.3.4)
  Type:  Hash
  Fields:
    - score        : int (1-100) anomaly score
    - sources      : comma-separated list of feed names
    - source_count : number of feeds this IP appeared in
    - last_updated : ISO date string

Why Redis Hash?
  1. O(1) lookup by IP address - perfect for the web app query pattern
  2. Multiple fields per key - stores score, sources, and metadata atomically
  3. Memory efficient - Redis optimizes small hashes with ziplist encoding
  4. No serialization needed - each field is independently readable/writable
"""

import redis
from datetime import datetime, timezone
from config import FEEDS, REDIS_HOST, REDIS_PORT, REDIS_DB, IP_TTL_SECONDS
from feeds import fetch_and_parse


def main():
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

    try:
        r.ping()
        print("[OK] Connected to Redis")
    except redis.ConnectionError:
        print("[FATAL] Cannot connect to Redis. Is it running?")
        return

    # Phase 1: Fetch all feeds and build ip -> sources mapping
    ip_sources: dict[str, list[str]] = {}
    successful_feeds = 0

    for feed in FEEDS:
        print(f"Fetching: {feed['name']}...")
        ips = fetch_and_parse(feed)
        if ips:
            successful_feeds += 1
            print(f"  Found {len(ips)} IPs")
            for ip in ips:
                ip_sources.setdefault(ip, []).append(feed["name"])
        else:
            print(f"  No IPs found (feed may be down)")

    if successful_feeds == 0:
        print("[FATAL] No feeds were successfully fetched. Aborting.")
        return

    # Phase 2: Calculate scores and store in Redis
    total_feeds = successful_feeds
    now = datetime.now(timezone.utc).isoformat()
    batch_size = 5000
    items = list(ip_sources.items())

    for i in range(0, len(items), batch_size):
        pipe = r.pipeline(transaction=False)
        batch = items[i:i + batch_size]
        for ip, sources in batch:
            source_count = len(sources)
            score = max(1, min(100, int((source_count / total_feeds) * 100)))
            key = f"ip:{ip}"
            pipe.hset(key, "score", str(score))
            pipe.hset(key, "sources", ",".join(sources))
            pipe.hset(key, "source_count", str(source_count))
            pipe.hset(key, "last_updated", now)
            pipe.expire(key, IP_TTL_SECONDS)
        pipe.execute()
        print(f"  Stored batch {i // batch_size + 1} ({len(batch)} IPs)")

    print(f"\n{'='*50}")
    print(f"Ingestion complete!")
    print(f"  Feeds fetched: {successful_feeds}/{len(FEEDS)}")
    print(f"  Unique IPs stored: {len(ip_sources)}")
    print(f"  IPs in multiple sources: {sum(1 for s in ip_sources.values() if len(s) > 1)}")
    print(f"  TTL: {IP_TTL_SECONDS // 3600} hours")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
