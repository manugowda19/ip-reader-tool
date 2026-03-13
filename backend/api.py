from flask import Flask, jsonify, request
import redis
from datetime import datetime, timezone
import json
import uuid

from collector import (
    get_redis,
    get_feeds,
    set_feeds,
    add_or_update_feed,
    remove_feed,
    run_collector,
    get_last_collect,
)

# -----------------------------
# Flask App
# -----------------------------
app = Flask(__name__)

# -----------------------------
# Redis Connection
# -----------------------------
r = get_redis()

RECENT_ACTIVITY_KEY = "recent_activity"
RECENT_ACTIVITY_MAX = 50


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_activity(activity_type: str, message: str, ip: str | None = None):
    event = {
        "id": str(uuid.uuid4()),
        "type": activity_type,
        "message": message,
        "ip": ip,
        "timestamp": _now_iso(),
    }
    if ip:
        data = r.hgetall(f"ip:{ip}")
        if data:
            event["first_seen"] = data.get("first_seen")
            event["last_seen"] = data.get("last_seen")
    r.lpush(RECENT_ACTIVITY_KEY, json.dumps(event))
    r.ltrim(RECENT_ACTIVITY_KEY, 0, RECENT_ACTIVITY_MAX - 1)


# -----------------------------
# Home Route
# -----------------------------
@app.route("/")
def home():

    return jsonify({
        "service": "Threat Intelligence API",
        "status": "running"
    })


# -----------------------------
# IP Reputation Lookup
# -----------------------------
@app.route("/ip/<ip>")
def ip_lookup(ip):

    key = f"ip:{ip}"

    data = r.hgetall(key)

    if not data:
        # Record clean IP lookups so we can track clean counts.
        # Store a minimal marker on the IP hash and add to a dedicated set.
        now = datetime.now(timezone.utc).isoformat()
        r.hset(key, "status", "clean")
        r.hset(key, "score", "0")
        r.hset(key, "first_seen", now)
        r.hset(key, "last_seen", now)
        r.sadd("clean_ips", ip)
        log_activity("clean", "Clean IP observed (not found in threat database)", ip)

        return jsonify({
            "ip": ip,
            "malicious": False,
            "message": "IP not found in threat database"
        })

    # If this IP was previously recorded as clean, return clean.
    if data.get("status") == "clean" or str(data.get("malicious", "")).lower() in ("0", "false", "clean"):
        r.sadd("clean_ips", ip)
        r.hset(key, "last_seen", _now_iso())
        log_activity("clean", "Clean IP checked", ip)
        return jsonify({
            "ip": ip,
            "malicious": False,
            "message": "IP marked clean"
        })

    sources = data.get("sources", "").split(",")
    r.hset(key, "last_seen", _now_iso())
    log_activity("malicious", "Malicious IP checked", ip)

    return jsonify({
        "ip": ip,
        "malicious": True,
        "score": int(data.get("score", 0)),
        "source_count": int(data.get("count", 0)),
        "sources": sources,
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen")
    })


# -----------------------------
# Top Malicious IPs
# -----------------------------
@app.route("/top")
def top_ips():

    ips = r.zrevrange("ip_scores", 0, 9, withscores=True)

    results = []

    for ip, score in ips:

        results.append({
            "ip": ip,
            "score": int(score)
        })

    return jsonify(results)


# -----------------------------
# Database Statistics
# -----------------------------
@app.route("/stats")
def stats():

    malicious = r.zcard("ip_scores")
    clean = r.scard("clean_ips")

    return jsonify({
        "malicious_ips": int(malicious),
        "clean_ips": int(clean),
        "total_tracked_ips": int(malicious) + int(clean),
    })


# -----------------------------
# Recent Activity
# -----------------------------
@app.route("/activity")
def activity():
    raw = r.lrange(RECENT_ACTIVITY_KEY, 0, 19)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            continue
    return jsonify(events)


# -----------------------------
# Admin: Feeds & Collector
# -----------------------------
@app.route("/admin/feeds", methods=["GET"])
def admin_list_feeds():
    feeds = get_feeds(r)
    return jsonify({"feeds": feeds})


@app.route("/admin/feeds", methods=["POST"])
def admin_add_feed():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    add_or_update_feed(r, name, url)
    return jsonify({"feeds": get_feeds(r)})


@app.route("/admin/feeds/<name>", methods=["DELETE"])
def admin_remove_feed(name):
    remove_feed(r, name)
    return jsonify({"feeds": get_feeds(r)})


@app.route("/admin/collect", methods=["POST"])
def admin_run_collect():
    result = run_collector(r)
    return jsonify(result)


@app.route("/admin/collect/status", methods=["GET"])
def admin_collect_status():
    last = get_last_collect(r)
    if last is None:
        return jsonify({"last_run": None})
    return jsonify({"last_run": last})


# -----------------------------
# Admin: Bulk IP Import
# -----------------------------
import re as _re
import requests as _requests

_IP_RE = _re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


# -----------------------------
# IP Geolocation + WHOIS
# -----------------------------
@app.route("/whois/<ip>")
def whois_lookup(ip):
    """
    Returns geolocation + WHOIS info for an IP using free APIs:
    - ip-api.com for geolocation
    - rdap.org for WHOIS/ownership
    """
    result = {
        "ip": ip,
        "geo": None,
        "whois": None,
    }

    # Geolocation via ip-api.com (free, no key needed, 45 req/min)
    try:
        geo_resp = _requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query,continent,currency,district,offset,reverse",
            timeout=5,
        )
        geo_data = geo_resp.json()
        if geo_data.get("status") == "success":
            result["geo"] = {
                "country": geo_data.get("country"),
                "country_code": geo_data.get("countryCode"),
                "continent": geo_data.get("continent"),
                "region": geo_data.get("regionName"),
                "city": geo_data.get("city"),
                "district": geo_data.get("district"),
                "zip": geo_data.get("zip"),
                "lat": geo_data.get("lat"),
                "lon": geo_data.get("lon"),
                "timezone": geo_data.get("timezone"),
                "utc_offset": geo_data.get("offset"),
                "currency": geo_data.get("currency"),
                "isp": geo_data.get("isp"),
                "org": geo_data.get("org"),
                "as_number": geo_data.get("as"),
                "as_name": geo_data.get("asname"),
                "reverse_dns": geo_data.get("reverse"),
                "is_mobile": geo_data.get("mobile"),
                "is_proxy": geo_data.get("proxy"),
                "is_hosting": geo_data.get("hosting"),
            }
    except Exception:
        pass

    # WHOIS via rdap.org (free, no key)
    try:
        rdap_resp = _requests.get(f"https://rdap.org/ip/{ip}", timeout=8)
        if rdap_resp.status_code == 200:
            rdap = rdap_resp.json()
            # Extract useful fields
            whois_info = {
                "name": rdap.get("name"),
                "handle": rdap.get("handle"),
                "type": rdap.get("type"),
                "start_address": rdap.get("startAddress"),
                "end_address": rdap.get("endAddress"),
                "country": rdap.get("country"),
                "parent_handle": rdap.get("parentHandle"),
                "status": rdap.get("status", []),
                "cidr": None,
            }

            # Extract CIDR
            cidrs = rdap.get("cidr0_cidrs", [])
            if cidrs:
                cidr_strs = []
                for c in cidrs:
                    v4 = c.get("v4prefix")
                    length = c.get("length")
                    if v4 and length:
                        cidr_strs.append(f"{v4}/{length}")
                if cidr_strs:
                    whois_info["cidr"] = ", ".join(cidr_strs)

            # Extract registration/update events
            for event in rdap.get("events", []):
                action = event.get("eventAction")
                date = event.get("eventDate")
                if action == "registration" and date:
                    whois_info["registration_date"] = date
                elif action == "last changed" and date:
                    whois_info["last_changed"] = date

            # Extract remarks/descriptions
            remarks = rdap.get("remarks", [])
            if remarks:
                desc_parts = []
                for remark in remarks:
                    title = remark.get("title", "")
                    descs = remark.get("description", [])
                    if descs:
                        desc_parts.append(f"{title}: {'; '.join(descs)}" if title else "; ".join(descs))
                if desc_parts:
                    whois_info["remarks"] = " | ".join(desc_parts[:3])

            # Extract entities (org name, abuse contact, addresses, phones)
            def _parse_entity(entity, whois_info):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []

                org_name = None
                email = None
                phone = None
                address = None
                for field in (vcard or []):
                    if isinstance(field, list) and len(field) > 3:
                        if field[0] == "fn":
                            org_name = field[3]
                        elif field[0] == "email":
                            email = field[3]
                        elif field[0] == "tel":
                            phone = field[3]
                        elif field[0] == "adr":
                            adr = field[3]
                            if isinstance(adr, list):
                                address = ", ".join(p for p in adr if p and isinstance(p, str))
                            elif isinstance(adr, str):
                                address = adr

                if "registrant" in roles or "administrative" in roles:
                    if org_name:
                        whois_info["org_name"] = org_name
                    if address:
                        whois_info["address"] = address
                    if phone:
                        whois_info["phone"] = phone
                if "abuse" in roles:
                    if email:
                        whois_info["abuse_email"] = email
                    if phone and "abuse_phone" not in whois_info:
                        whois_info["abuse_phone"] = phone
                    if org_name and "org_name" not in whois_info:
                        whois_info["org_name"] = org_name
                if "technical" in roles:
                    if email and "tech_email" not in whois_info:
                        whois_info["tech_email"] = email

                # Check nested entities
                for sub in entity.get("entities", []):
                    _parse_entity(sub, whois_info)

            entities = rdap.get("entities", [])
            for entity in entities:
                _parse_entity(entity, whois_info)

            result["whois"] = whois_info
    except Exception:
        pass

    return jsonify(result)


@app.route("/admin/bulk/extract", methods=["POST"])
def admin_bulk_extract():
    """Step 1: Extract unique IPs from raw text. No storage."""
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "text field is required"}), 400

    found_ips = list(dict.fromkeys(_IP_RE.findall(text)))
    return jsonify({"total_extracted": len(found_ips), "ips": found_ips})


@app.route("/admin/bulk/submit", methods=["POST"])
def admin_bulk_submit():
    """
    Step 2: Admin submits extracted IPs with a source name and malicious/clean label.
    Stores them into Redis.
    """
    import time as _time

    data = request.get_json(force=True, silent=True) or {}
    ips = data.get("ips", [])
    source_name = (data.get("source", "") or "").strip()
    label = (data.get("label", "") or "").strip().lower()  # "malicious" or "clean"

    if not ips:
        return jsonify({"error": "ips list is required"}), 400
    if not source_name:
        return jsonify({"error": "source name is required"}), 400
    if label not in ("malicious", "clean"):
        return jsonify({"error": "label must be 'malicious' or 'clean'"}), 400

    current_time = int(_time.time())
    total_feeds_count = max(1, r.hlen("config:feeds") or 8)
    submitted = 0

    for ip in ips:
        key = f"ip:{ip}"

        if label == "clean":
            r.hset(key, "status", "clean")
            r.hset(key, "score", "0")
            r.hset(key, "sources", source_name)
            r.hset(key, "first_seen", str(current_time))
            r.hset(key, "last_seen", str(current_time))
            r.sadd("clean_ips", ip)
            # Remove from malicious set if present
            r.zrem("ip_scores", ip)
        else:
            existing = r.hgetall(key)
            if existing and existing.get("status") != "clean" and existing.get("sources"):
                # Already malicious — add source
                source_set = set(existing["sources"].split(","))
                source_set.add(source_name)
                new_count = len(source_set)
                new_score = min(100, int((new_count / total_feeds_count) * 100))
                r.hset(key, "sources", ",".join(sorted(source_set)))
                r.hset(key, "count", str(new_count))
                r.hset(key, "score", str(new_score))
                r.hset(key, "last_seen", str(current_time))
                r.zadd("ip_scores", {ip: new_score})
            else:
                # New malicious entry
                r.hset(key, "score", "12")
                r.hset(key, "count", "1")
                r.hset(key, "sources", source_name)
                r.hset(key, "first_seen", str(current_time))
                r.hset(key, "last_seen", str(current_time))
                r.zadd("ip_scores", {ip: 12})
                r.expire(key, 604800)
            # Remove from clean if it was there
            r.srem("clean_ips", ip)
            if r.hexists(key, "status"):
                r.hdel(key, "status")

        submitted += 1

    # Track this manual source in Redis
    r.hset("config:manual_feeds", source_name, json.dumps({
        "label": label,
        "ip_count": len(ips),
        "added_at": _now_iso(),
    }))

    return jsonify({
        "total_submitted": submitted,
        "source": source_name,
        "label": label,
    })


# -----------------------------
# Admin: Manual Feeds (Bulk Imports)
# -----------------------------
@app.route("/admin/manual_feeds", methods=["GET"])
def admin_list_manual_feeds():
    """List all manually added feed sources (from bulk IP imports)."""
    raw = r.hgetall("config:manual_feeds")
    feeds = {}
    for name, data_str in raw.items():
        try:
            feeds[name] = json.loads(data_str)
        except Exception:
            feeds[name] = {"label": "unknown", "ip_count": 0, "added_at": ""}
    return jsonify({"manual_feeds": feeds})


@app.route("/admin/manual_feeds/<name>", methods=["DELETE"])
def admin_remove_manual_feed(name):
    """Remove a manual feed source and all its IPs from Redis."""
    r.hdel("config:manual_feeds", name)

    cursor = 0
    while True:
        cursor, keys = r.scan(cursor, match="ip:*", count=1000)
        for key in keys:
            sources = r.hget(key, "sources")
            if sources and name in sources:
                source_set = set(sources.split(","))
                source_set.discard(name)
                if not source_set:
                    ip_addr = key.replace("ip:", "")
                    r.delete(key)
                    r.zrem("ip_scores", ip_addr)
                    r.srem("clean_ips", ip_addr)
                else:
                    total_feeds_count = max(1, r.hlen("config:feeds") or 8)
                    new_count = len(source_set)
                    new_score = min(100, int((new_count / total_feeds_count) * 100))
                    r.hset(key, "sources", ",".join(sorted(source_set)))
                    r.hset(key, "count", str(new_count))
                    r.hset(key, "score", str(new_score))
                    ip_addr = key.replace("ip:", "")
                    r.zadd("ip_scores", {ip_addr: new_score})
        if cursor == 0:
            break

    return jsonify({"deleted": name})


# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000, debug=True)
