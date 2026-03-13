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
        r.hset(key, mapping={
            "status": "clean",
            "score": "0",
            "first_seen": now,
            "last_seen": now,
        })
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
# Run Server
# -----------------------------
if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000, debug=True)
