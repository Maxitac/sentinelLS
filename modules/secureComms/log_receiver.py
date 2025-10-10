# log_receiver.py — secure receiver using SecretBox
from flask import Flask, request, jsonify
import json
import os
from datetime import datetime
import base64
from nacl.secret import SecretBox

# === Configuration ===
SAVE_FILE = "received_logs.jsonl"
KEYS_FILE = "agent_keys.json"   # controller's registry from registration

app = Flask(__name__)

# Ensure log storage exists
if not os.path.exists(SAVE_FILE):
    with open(SAVE_FILE, "w") as f:
        pass

def load_agent_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

@app.route("/ingest", methods=["POST"])
def ingest_log():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON payload"}), 400

        # Expecting agent_id and payload (base64)
        agent_id = data.get("agent_id")
        b64_payload = data.get("payload")
        if not agent_id or not b64_payload:
            return jsonify({"error": "Missing agent_id or payload"}), 400

        # Lookup shared key for this agent
        agent_keys = load_agent_keys()
        if agent_id not in agent_keys:
            return jsonify({"error": "Unknown agent_id"}), 404

        secret_hex = agent_keys[agent_id].get("secret_key")
        if not secret_hex:
            return jsonify({"error": "No secret key for agent"}), 500

        shared_key = bytes.fromhex(secret_hex)
        box = SecretBox(shared_key)

        # Decode base64 and decrypt
        try:
            encrypted = base64.b64decode(b64_payload)
            plaintext = box.decrypt(encrypted)   # will raise if tampered or wrong key
        except Exception as e:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

        # Parse the original log JSON
        log_entry = json.loads(plaintext.decode())

        # Basic schema validation
        required_fields = {"source_id", "source_type", "timestamp", "rawlog"}
        if not all(field in log_entry for field in required_fields):
            return jsonify({"error": "Invalid log format after decryption"}), 400

        # Append decrypted log to file (JSON Lines)
        with open(SAVE_FILE, "a") as f:
            f.write(json.dumps({"agent_id": agent_id, **log_entry}) + "\n")

        # Console monitor
        print(f"[{datetime.utcnow().isoformat()}Z] Received secure log from {agent_id} -> {log_entry['source_id']}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("[*] Starting secure log receiver on http://0.0.0.0:7777/ingest")
    app.run(host="0.0.0.0", port=7777)
