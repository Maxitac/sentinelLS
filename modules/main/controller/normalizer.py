import sqlite3
import json
import re
import datetime
import time # <--- 1. Import time module

DB_FILE = "logs.db"
PATTERNS_FILE = "patterns.json"
SLEEP_INTERVAL_SECONDS = 30 # <--- Define a sleep interval

def load_patterns():
    # ... (this function remains unchanged)
    with open(PATTERNS_FILE, "r") as f:
        return json.load(f)

def normalize_log(rawlog, source_type, patterns):
    # ... (this function remains unchanged)
    if source_type not in patterns:
        return None
    for p in patterns[source_type]["patterns"]:
        match = re.match(p["regex"], rawlog)
        if match:
            data = match.groupdict()
            data["pattern_name"] = p["name"]
            return data
    return None

def init_db():
    # ... (this function remains unchanged)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS normalized_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER, agent_id TEXT, source_type TEXT, timestamp TEXT,
            hostname TEXT, process TEXT, pid TEXT, username TEXT, ip TEXT,
            port TEXT, protocol TEXT, event TEXT, pattern_name TEXT,
            normalized_at TEXT,
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS unknown_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, log_id INTEGER, agent_id TEXT,
            source_type TEXT, rawlog TEXT, reason TEXT, captured_at TEXT,
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)
    conn.commit()
    conn.close()

# --- MODIFIED FUNCTION ---
def normalize_new_logs(conn): # <--- 2. Accept a database connection
    """Normalizes new logs and returns the count of processed logs."""
    cur = conn.cursor()

    # Query remains the same
    cur.execute("""
        SELECT l.id, l.agent_id, l.source_type, l.rawlog FROM logs l
        WHERE l.id NOT IN (
            SELECT log_id FROM normalized_logs UNION SELECT log_id FROM unknown_logs
        )
    """)
    rows = cur.fetchall()

    if not rows:
        # Don't print here anymore, let the main loop handle the message
        return 0 # <--- 3. Return 0 if no new logs

    patterns = load_patterns()
    
    # ... (The for loop for processing rows remains exactly the same)
    for row in rows:
        log_id, agent_id, source_type, rawlog = row
        result = normalize_log(rawlog, source_type, patterns)
        if result:
            # ... (INSERT into normalized_logs logic)
            fields = (log_id, agent_id, source_type, result.get("timestamp"),
                      result.get("hostname"), result.get("process", "sshd"),
                      result.get("pid"), result.get("username"), result.get("ip"),
                      result.get("port"), result.get("protocol"),
                      result.get("event", result.get("pattern_name")),
                      result.get("pattern_name"),
                      datetime.datetime.now(datetime.UTC).isoformat())
            cur.execute("INSERT INTO normalized_logs (log_id, agent_id, source_type, timestamp, hostname, process, pid, username, ip, port, protocol, event, pattern_name, normalized_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", fields)
        else:
            # ... (INSERT into unknown_logs logic)
            reason = "No matching regex found for source_type"
            cur.execute("INSERT INTO unknown_logs (log_id, agent_id, source_type, rawlog, reason, captured_at) VALUES (?, ?, ?, ?, ?, ?)", (log_id, agent_id, source_type, rawlog, reason, datetime.datetime.now(datetime.UTC).isoformat()))
    
    conn.commit()
    # Don't close the connection here
    
    return len(rows) # <--- 4. Return the number of logs processed

# --- NEW MAIN FUNCTION AND ENTRY POINT ---
def main():
    """Main function to run the normalization process in a loop."""
    init_db()
    conn = sqlite3.connect(DB_FILE)
    print(f"[*] Starting periodic log normalization. Checking every {SLEEP_INTERVAL_SECONDS} seconds.")
    print("[*] Press Ctrl+C to stop.")

    try:
        while True:
            processed_count = normalize_new_logs(conn)
            
            if processed_count > 0:
                print(f"[+] Successfully normalized {processed_count} log(s). Checking for more...")
                # Continue the loop immediately to process any other new logs
            else:
                print("[*] No new logs found. Sleeping...")
                time.sleep(SLEEP_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received. Exiting.")
    finally:
        # Ensure the database connection is always closed
        if conn:
            conn.close()
            print("[*] Database connection closed.")

if __name__ == "__main__":
    main()