# multi_scrapper.py — secure version using SecretBox
import json
import threading
import time
import requests
from datetime import datetime
import os
import base64

from nacl.secret import SecretBox

CONFIG = {}

AGENT_INFO_FILE = "agent_info.json"

def load_agent_info():
    if not os.path.exists(AGENT_INFO_FILE):
        return None
    with open(AGENT_INFO_FILE, "r") as f:
        return json.load(f)

def tail_log(source, server_url, box, agent_id):
    path = source["log_path"]
    source_id = source["source_id"]
    source_type = source["source_type"]

    if not os.path.exists(path):
        print(f"[!] Log file not found for {source_type}: {path}")
        return

    print(f"[*] Monitoring {source_type} logs at {path}")

    with open(path, "r") as f:
        f.seek(0, 2)  # move to end of existing file

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            payload = {
                "source_id": source_id,
                "source_type": source_type,
                "timestamp": datetime.utcnow().isoformat(),
                "rawlog": line.strip()
            }

            try:
                plaintext = json.dumps(payload).encode()
                encrypted = box.encrypt(plaintext)         # returns bytes: nonce + ciphertext + tag
                b64 = base64.b64encode(encrypted).decode()  # safe for JSON

                out = {
                    "agent_id": agent_id,
                    "payload": b64
                }

                res = requests.post(server_url, json=out, timeout=5)
                if res.status_code != 200:
                    print(f"[!] Server responded with {res.status_code}: {res.text}")
            except requests.exceptions.RequestException as e:
                print(f"[!] Error sending {source_type} log: {e}")
                time.sleep(2)
            except Exception as e:
                print(f"[!] Error preparing/encrypting log: {e}")
                time.sleep(1)

def main():
    global CONFIG

    config_path = "config.json"
    if not os.path.exists(config_path):
        print("[x] config.json not found! Please create it first.")
        return

    with open(config_path, "r") as f:
        CONFIG = json.load(f)

    # Load agent_info (must exist from registration)
    agent_info = load_agent_info()
    if not agent_info:
        print("[x] agent_info.json not found. Run the registration agent.py first.")
        return

    agent_id = agent_info.get("agent_id")
    shared_hex = agent_info.get("shared_secret_key")
    if not agent_id or not shared_hex:
        print("[x] agent_info.json missing fields. Re-register the agent.")
        return

    shared_key = bytes.fromhex(shared_hex)
    box = SecretBox(shared_key)
    server_url = CONFIG.get("server_url")
    if not server_url:
        print("[x] server_url missing from config.json")
        return

    print(f"[*] Forwarding encrypted logs to {server_url} as agent {agent_id}")

    threads = []
    for src in CONFIG.get("sources", []):
        t = threading.Thread(target=tail_log, args=(src, server_url, box, agent_id), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down gracefully...")

if __name__ == "__main__":
    main()
