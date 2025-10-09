import os
import socket
import json
import datetime
import requests

# === Configuration ===
LOG_FILE = "/var/log/auth.log"   # OpenSSH logs appear here on Debian
SERVER_URL = "http://192.168.100.138:7777/ingest"
SOURCE_TYPE = "openssh"
SOURCE_ID = socket.gethostname()  # can be hostname, UUID, or manually set

# === Functions ===
def format_log_entry(raw_line):
    """
    Wrap a raw log line into a lightweight JSON structure.
    """
    # Convert timestamp to ISO 8601 UTC (best practice for logs)
    now_utc = datetime.datetime.utcnow().isoformat() + "Z"
    
    return {
        "source_id": SOURCE_ID,
        "source_type": SOURCE_TYPE,
        "timestamp": now_utc,
        "rawlog": raw_line.strip()
    }

def tail_file(filename):
    """
    Generator that yields new lines as they are written to a file.
    Similar to `tail -f`.
    """
    with open(filename, "r") as f:
        f.seek(0, os.SEEK_END)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                continue  # wait until new line arrives
            yield line

def send_log(entry):
    """
    Send a JSON log entry to the remote server.
    """
    try:
        response = requests.post(SERVER_URL, json=entry, timeout=5)
        response.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to send log: {e}")

# === Main ===
if __name__ == "__main__":
    print(f"[*] Collecting OpenSSH logs from {LOG_FILE} and forwarding to {SERVER_URL}")
    for line in tail_file(LOG_FILE):
        log_entry = format_log_entry(line)
        send_log(log_entry)
