import requests
import re

# -----------------------------
# Threat Intelligence Feeds
# -----------------------------
FEEDS = {
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "CINSscore": "https://cinsscore.com/list/ci-badguys.txt",
    "FireHOL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
    "ThreatView": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
}

# -----------------------------
# Regex for IPv4 extraction
# -----------------------------
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# -----------------------------
# Output file
# -----------------------------
OUTPUT_FILE = "sample_ips.txt"

# Clear previous output
open(OUTPUT_FILE, "w").close()

print("\n===== Threat Feed Preview =====\n")

for name, url in FEEDS.items():

    print(f"\n===== {name} =====")

    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()

        content = response.text

        # Extract IPs
        ips = IP_REGEX.findall(content)

        unique_ips = list(set(ips))

        print(f"Total IPs found: {len(unique_ips)}")

        print("\nSample IPs:")

        # Print first 10
        for ip in unique_ips[:10]:
            print(ip)

        # Save first 100 to file
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"\n===== {name} =====\n")
            for ip in unique_ips[:100]:
                f.write(ip + "\n")

    except Exception as e:
        print("Error fetching feed:", e)

print("\nPreview complete.")
print(f"Sample IPs saved to: {OUTPUT_FILE}")
