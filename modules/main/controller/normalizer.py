import sqlite3
import json
import re
import datetime

DB_FILE = "logs.db"
PATTERNS_FILE = "patterns.json"

def load_patterns():
    with open(PATTERNS_FILE, "r") as f:
        return json.load(f)

def normalize_log(rawlog, source_type, patterns):
    """
    Tries to match a raw log string with known regex patterns.
    Returns a normalized dict if match found, else None.
    """
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
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Table for normalized logs
    cur.execute("""
        CREATE TABLE IF NOT EXISTS normalized_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            agent_id TEXT,
            source_type TEXT,
            timestamp TEXT,
            hostname TEXT,
            process TEXT,
            pid TEXT,
            username TEXT,
            ip TEXT,
            port TEXT,
            protocol TEXT,
            event TEXT,
            pattern_name TEXT,
            normalized_at TEXT,
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)

    # Table for unknown/unmatched logs
    cur.execute("""
        CREATE TABLE IF NOT EXISTS unknown_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            agent_id TEXT,
            source_type TEXT,
            rawlog TEXT,
            reason TEXT,
            captured_at TEXT,
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)

    conn.commit()
    conn.close()

def normalize_new_logs():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Fetch logs not yet normalized or marked unknown
    cur.execute("""
        SELECT l.id, l.agent_id, l.source_type, l.rawlog
        FROM logs l
        WHERE l.id NOT IN (
            SELECT log_id FROM normalized_logs
            UNION
            SELECT log_id FROM unknown_logs
        )
    """)
    rows = cur.fetchall()

    if not rows:
        print("[*] No new logs to normalize.")
        conn.close()
        return

    patterns = load_patterns()

    for row in rows:
        log_id, agent_id, source_type, rawlog = row
        result = normalize_log(rawlog, source_type, patterns)
        if result:
            fields = (
                log_id,
                agent_id,
                source_type,
                result.get("timestamp"),
                result.get("hostname"),
                result.get("process", "sshd"),
                result.get("pid"),
                result.get("username"),
                result.get("ip"),
                result.get("port"),
                result.get("protocol"),
                result.get("event", result.get("pattern_name")),
                result.get("pattern_name"),
                datetime.datetime.now(datetime.UTC).isoformat()
            )
            cur.execute("""
                INSERT INTO normalized_logs (
                    log_id, agent_id, source_type, timestamp, hostname,
                    process, pid, username, ip, port, protocol,
                    event, pattern_name, normalized_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, fields)
            print(f"[+] Normalized log {log_id} ({result['pattern_name']})")
        else:
            # Insert into unknown_logs if no match
            reason = "No matching regex found for source_type"
            cur.execute("""
                INSERT INTO unknown_logs (
                    log_id, agent_id, source_type, rawlog, reason, captured_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                log_id,
                agent_id,
                source_type,
                rawlog,
                reason,
                datetime.datetime.now(datetime.UTC).isoformat()
            ))
            print(f"[!] No pattern matched for log {log_id} — stored in unknown_logs")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    normalize_new_logs()
