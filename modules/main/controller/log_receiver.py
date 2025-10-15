from flask import Flask, request, jsonify
import json, os, base64, sqlite3
import datetime
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

KEYS_FILE = "agent_keys.json"
DB_FILE = "logs.db"

app = Flask(__name__)

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            source_id TEXT,
            source_type TEXT,
            timestamp TEXT,
            rawlog TEXT,
            received_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# --- Load agent keys ---
def load_agent_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

# --- Ingestion endpoint ---
@app.route("/ingest", methods=["POST"])
def ingest_log():
    try:
        data = request.get_json(force=True)
        agent_id = data.get("agent_id")
        payload_b64 = data.get("payload")

        if not agent_id or not payload_b64:
            return jsonify({"error": "Missing fields"}), 400

        # Retrieve shared key
        keys = load_agent_keys()
        if agent_id not in keys:
            return jsonify({"error": "Unrecognized agent"}), 403

        shared_key = bytes.fromhex(keys[agent_id]["secret_key"])

        # Decrypt payload
        box = SecretBox(shared_key)
        encrypted = base64.b64decode(payload_b64)
        decrypted = box.decrypt(encrypted)
        log_data = json.loads(decrypted.decode())

        # Save to SQLite
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs (agent_id, source_id, source_type, timestamp, rawlog, received_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            agent_id,
            log_data["source_id"],
            log_data["source_type"],
            log_data["timestamp"],
            log_data["rawlog"],
            datetime.datetime.now(datetime.UTC).isoformat()

        ))
        conn.commit()
        conn.close()

        print(f"[+] Log from {agent_id}/{log_data['source_type']}")
        return jsonify({"status": "success"}), 200

    except CryptoError:
        return jsonify({"error": "Decryption failed"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    init_db()
    print("[*] Secure log receiver running on http://0.0.0.0:7777/ingest")
    app.run(host="0.0.0.0", port=7777, debug=True)
