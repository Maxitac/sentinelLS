from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

# === Configuration ===
SAVE_FILE = "received_logs.jsonl"

app = Flask(__name__)

# Ensure log storage file exists
if not os.path.exists(SAVE_FILE):
    with open(SAVE_FILE, "w") as f:
        pass  # create empty file

@app.route("/ingest", methods=["POST"])
def ingest_log():
    """
    Endpoint to receive logs from clients.
    """
    try:
        data = request.get_json(force=True)

        # Basic schema validation
        required_fields = {"source_id", "source_type", "timestamp", "rawlog"}
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Invalid log format"}), 400

        # Append log entry to file (JSON Lines format)
        with open(SAVE_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")

        # Print to console for monitoring
        print(f"[{datetime.utcnow().isoformat()}Z] Received log from {data['source_id']} ({data['source_type']})")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("[*] Starting log receiver on http://0.0.0.0:7777/ingest")
    app.run(host="0.0.0.0", port=7777, debug=True)
