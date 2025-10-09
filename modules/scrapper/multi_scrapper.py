import json
import threading
import time
import requests
from datetime import datetime
import os

CONFIG = {}

def tail_log(source):
    path = source["log_path"]
    source_id = source["source_id"]
    source_type = source["source_type"]
    server_url = CONFIG["server_url"]

    # Ensure the log file exists
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
                res = requests.post(server_url, json=payload, timeout=5)
                if res.status_code != 200:
                    print(f"[!] Server responded with {res.status_code}: {res.text}")
            except requests.exceptions.RequestException as e:
                print(f"[!] Error sending {source_type} log: {e}")
                time.sleep(2)

def main():
    global CONFIG

    # Load config file
    config_path = "config.json"
    if not os.path.exists(config_path):
        print("[x] config.json not found! Please create it first.")
        return

    with open(config_path, "r") as f:
        CONFIG = json.load(f)

    print(f"[*] Forwarding logs to {CONFIG['server_url']}")

    # Spawn a thread for each log source
    threads = []
    for src in CONFIG["sources"]:
        t = threading.Thread(target=tail_log, args=(src,), daemon=True)
        t.start()
        threads.append(t)

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down gracefully...")

if __name__ == "__main__":
    main()
