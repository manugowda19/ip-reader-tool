REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
IP_TTL_SECONDS = 7 * 24 * 3600  # 7 days

FEEDS = [
    {
        "name": "abuse.ch SSL IPBL",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "format": "csv",
    },
    {
        "name": "Feodo IP Blocklist",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "format": "csv",
    },
    {
        "name": "firehol_level1",
        "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
        "format": "freetext",
    },
    {
        "name": "IPsum",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "format": "freetext",
    },
    {
        "name": "Threatview.io",
        "url": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
        "format": "freetext",
    },
    {
        "name": "SSH Bruteforce (Honeynet)",
        "url": "https://feeds.honeynet.asia/bruteforce/latest-sshbruteforce-unique.csv",
        "format": "csv",
    },
    {
        "name": "Telnet Bruteforce (Honeynet)",
        "url": "https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv",
        "format": "csv",
    },
    {
        "name": "Tor Exit Nodes",
        "url": "https://www.dan.me.uk/torlist/?exit",
        "format": "freetext",
    },
]
