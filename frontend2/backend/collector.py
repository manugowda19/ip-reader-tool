"""
Shared threat-intel collector: fetch feeds and store IPs in Redis.
Used by the API admin panel and optionally by the CLI script.
Redis key format: ip:<ip> with first_seen, last_seen (unix), score, count, sources.
"""
import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import requests
import redis

# -----------------------------
# Config
# -----------------------------
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
FEEDS_CONFIG_KEY = "config:feeds"
COLLECT_LAST_KEY = "config:collect_last"
TTL_SECONDS = 604800  # 7 days
PIPELINE_BATCH = 2000
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

DEFAULT_FEEDS = {
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "CINSscore": "https://cinsscore.com/list/ci-badguys.txt",
    "FireHOL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
    "MalSilo": "https://malsilo.gitlab.io/feeds/dumps/ip.txt",
    "ThreatView": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
}


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_feeds(r: redis.Redis) -> dict[str, str]:
    """Return feed name -> url from Redis, or default feeds. Seeds Redis if empty."""
    raw = r.hgetall(FEEDS_CONFIG_KEY)
    if raw:
        return dict(raw)
    # Seed with defaults
    if DEFAULT_FEEDS:
        r.hset(FEEDS_CONFIG_KEY, mapping=DEFAULT_FEEDS)
    return dict(DEFAULT_FEEDS)


def set_feeds(r: redis.Redis, feeds: dict[str, str]) -> None:
    """Replace stored feeds with the given dict."""
    r.delete(FEEDS_CONFIG_KEY)
    if feeds:
        r.hset(FEEDS_CONFIG_KEY, mapping=feeds)


def add_or_update_feed(r: redis.Redis, name: str, url: str) -> None:
    r.hset(FEEDS_CONFIG_KEY, name, url)


def remove_feed(r: redis.Redis, name: str) -> None:
    r.hdel(FEEDS_CONFIG_KEY, name)


def _now_ts() -> int:
    return int(time.time())


def _fetch_feed(name: str, url: str) -> tuple[str, set[str], str | None]:
    """Fetch a single feed. Returns (name, set of ips, error_message or None)."""
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        ips = set(IP_REGEX.findall(response.text))
        return name, ips, None
    except Exception as e:
        return name, set(), str(e)


def _calculate_score(source_count: int, total_feeds: int) -> int:
    if total_feeds <= 0:
        return 0
    return min(100, int((source_count / total_feeds) * 100))


def _store_ips(r: redis.Redis, ip_sources: dict[str, set[str]], total_feeds: int) -> None:
    pipe = r.pipeline()
    current_time = _now_ts()
    counter = 0
    for ip, sources in ip_sources.items():
        key = f"ip:{ip}"
        source_list = ",".join(sorted(sources))
        count = len(sources)
        score = _calculate_score(count, total_feeds)
        pipe.hsetnx(key, "first_seen", current_time)
        pipe.hset(
            key,
            mapping={
                "score": score,
                "count": count,
                "sources": source_list,
                "last_seen": current_time,
            },
        )
        pipe.expire(key, TTL_SECONDS)
        pipe.zadd("ip_scores", {ip: score})
        counter += 1
        if counter % PIPELINE_BATCH == 0:
            pipe.execute()
            pipe = r.pipeline()
    pipe.execute()


def run_collector(r: redis.Redis | None = None) -> dict:
    """
    Load feeds from Redis (or default), fetch all, store IPs in same Redis.
    Returns dict: ips_count, duration_seconds, feed_results [{ name, ips_count, error? }], error?
    """
    if r is None:
        r = get_redis()
    feeds = get_feeds(r)
    if not feeds:
        return {
            "ips_count": 0,
            "duration_seconds": 0,
            "feed_results": [],
            "error": "No feeds configured",
        }
    total_feeds = len(feeds)
    start = time.time()
    ip_sources = defaultdict(set)
    feed_results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_fetch_feed, name, url) for name, url in feeds.items()]
        for fut in futures:
            name, ips, err = fut.result()
            feed_results.append({
                "name": name,
                "ips_count": len(ips),
                "error": err,
            })
            for ip in ips:
                ip_sources[ip].add(name)

    try:
        _store_ips(r, ip_sources, total_feeds)
    except Exception as e:
        return {
            "ips_count": len(ip_sources),
            "duration_seconds": round(time.time() - start, 2),
            "feed_results": feed_results,
            "error": str(e),
        }

    duration = round(time.time() - start, 2)
    result = {
        "ips_count": len(ip_sources),
        "duration_seconds": duration,
        "feed_results": feed_results,
        "error": None,
    }
    # Persist last run for admin UI
    r.hset(
        COLLECT_LAST_KEY,
        mapping={
            "last_run": _now_ts(),
            "ips_count": len(ip_sources),
            "duration_seconds": str(duration),
            "feed_count": str(len(feeds)),
        },
    )
    return result


def get_last_collect(r: redis.Redis) -> dict | None:
    """Return last collect run info from Redis, or None."""
    raw = r.hgetall(COLLECT_LAST_KEY)
    if not raw:
        return None
    return {
        "last_run": int(raw.get("last_run", 0)),
        "ips_count": int(raw.get("ips_count", 0)),
        "duration_seconds": float(raw.get("duration_seconds", 0)),
        "feed_count": int(raw.get("feed_count", 0)),
    }
