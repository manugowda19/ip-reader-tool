import re
import requests

IP_REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)


def fetch_and_parse(feed: dict) -> set:
    """Fetch a feed URL and extract valid IPv4 addresses."""
    try:
        resp = requests.get(feed["url"], timeout=60, headers={"User-Agent": "MISP-Feed-Ingester/1.0"})
        resp.raise_for_status()
    except Exception as e:
        print(f"  [ERROR] Failed to fetch {feed['name']}: {e}")
        return set()

    ips = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        match = IP_REGEX.match(line)
        if match:
            ip = match.group(1)
            try:
                if is_valid_ip(ip):
                    ips.add(ip)
            except ValueError:
                continue

    return ips
