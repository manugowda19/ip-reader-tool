from flask import Flask, request, jsonify
from flask_cors import CORS
import redis

app = Flask(__name__)
CORS(app)

r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)


@app.route("/api/lookup")
def lookup():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter is required"}), 400

    data = r.hgetall(f"ip:{ip}")
    if not data:
        return jsonify({
            "ip": ip,
            "found": False,
            "score": 0,
            "sources": [],
            "source_count": 0,
            "last_updated": None,
        })

    return jsonify({
        "ip": ip,
        "found": True,
        "score": int(data["score"]),
        "sources": data["sources"].split(","),
        "source_count": int(data["source_count"]),
        "last_updated": data["last_updated"],
    })


@app.route("/api/stats")
def stats():
    """Returns basic stats about the stored threat data."""
    cursor = 0
    total = 0
    multi_source = 0
    while True:
        cursor, keys = r.scan(cursor, match="ip:*", count=1000)
        for key in keys:
            total += 1
            count = r.hget(key, "source_count")
            if count and int(count) > 1:
                multi_source += 1
        if cursor == 0:
            break

    return jsonify({
        "total_ips": total,
        "multi_source_ips": multi_source,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
