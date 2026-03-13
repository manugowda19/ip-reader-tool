import requests
import redis
import re
import time
from collections import defaultdict

# -----------------------------
# Redis Connection
# -----------------------------
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# -----------------------------
# Threat Intelligence Feeds
# -----------------------------
FEEDS = {
    "FireHOL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "CINSscore": "https://cinsscore.com/list/ci-badguys.txt",
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "FeodoTracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
    "ThreatView": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
}

TOTAL_FEEDS = len(FEEDS)

# IPv4 Regex
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Storage
ip_sources = defaultdict(set)


# -----------------------------
# Fetch Feed
# -----------------------------
def fetch_feed(name, url):

    print(f"\n[+] Fetching {name}")

    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()

        ips = set(IP_REGEX.findall(response.text))

        print(f"[✓] {name}: {len(ips)} IPs collected")

        for ip in ips:
            ip_sources[ip].add(name)

    except Exception as e:
        print(f"[!] Error fetching {name}: {e}")


# -----------------------------
# Threat Score Calculation
# -----------------------------
def calculate_score(source_count):

    score = int((source_count / TOTAL_FEEDS) * 100)

    return score


# -----------------------------
# Store in Redis
# -----------------------------
def store_to_redis():

    print("\n[+] Writing to Redis...")

    pipe = r.pipeline()

    for ip, sources in ip_sources.items():

        count = len(sources)

        score = calculate_score(count)

        pipe.hset(
            f"ip:{ip}",
            mapping={
                "score": score,
                "count": count,
                "sources": ",".join(sources)
            }
        )

        pipe.zadd("ip_scores", {ip: score})

    pipe.execute()

    print(f"[✓] Stored {len(ip_sources)} IPs in Redis")


# -----------------------------
# Show Summary
# -----------------------------
def print_summary():

    print("\n===== COLLECTION SUMMARY =====")

    print("Total unique IPs:", len(ip_sources))

    print("\nSample entries:\n")

    for i, (ip, sources) in enumerate(ip_sources.items()):

        print(f"{ip} → sources={list(sources)} count={len(sources)}")

        if i >= 10:
            break


# -----------------------------
# Main
# -----------------------------
def main():

    print("\n===== Threat Intelligence Collector =====")

    for name, url in FEEDS.items():

        fetch_feed(name, url)

        time.sleep(1)

    print_summary()

    store_to_redis()

    print("\n[✓] Collector completed successfully")


if __name__ == "__main__":
    main()
