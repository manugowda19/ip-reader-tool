"""
CLI entrypoint for threat intel collection.
Uses the same Redis and feed config as the API admin panel (config:feeds).
"""
from collector import get_redis, get_feeds, run_collector

if __name__ == "__main__":
    r = get_redis()
    feeds = get_feeds(r)
    print(f"[INFO] Using {len(feeds)} feeds from config")
    result = run_collector(r)
    if result.get("error"):
        print(f"[ERROR] {result['error']}")
    else:
        print(f"[INFO] Stored {result['ips_count']} IPs in {result['duration_seconds']}s")
