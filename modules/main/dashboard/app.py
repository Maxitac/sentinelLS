from flask import Flask, render_template, jsonify, request, abort
from flask_httpauth import HTTPTokenAuth
from flask_talisman import Talisman
from dotenv import load_dotenv
import sqlite3
import os
import json
import pandas as pd
from datetime import datetime

# --- Load environment variables ---
load_dotenv()

# --- Configuration ---
DB_FILE = os.getenv("DB_FILE", "logs.db")
API_TOKEN = os.getenv("DASHBOARD_TOKEN", "default-dev-token")  # change in .env!
APP_PORT = int(os.getenv("APP_PORT", 8443))
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"

# --- Flask app setup ---
app = Flask(__name__)
talisman = Talisman(
    app,
    content_security_policy={
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"]
    },
    force_https=True,
    strict_transport_security=True
)
auth = HTTPTokenAuth(scheme="Bearer")

# --- Token verification ---
TOKENS = {API_TOKEN: "analyst"}

@auth.verify_token
def verify_token(token):
    return TOKENS.get(token)

# --- Database utilities ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def fetch_analysis_results(limit=100):
    conn = get_db_connection()
    query = """
        SELECT id, log_ids, source_type, anomaly_type, severity, confidence, summary, analyzed_at
        FROM analysis_results
        ORDER BY id DESC
        LIMIT ?
    """
    rows = conn.execute(query, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

# --- Routes ---
@app.route("/")
@auth.login_required
def index():
    """Render dashboard HTML."""
    return render_template("index.html")

@app.route("/api/results", methods=["GET"])
@auth.login_required
def get_results():
    """Return recent analysis results as JSON."""
    limit = int(request.args.get("limit", 50))
    results = fetch_analysis_results(limit)
    return jsonify(results)

@app.route("/api/result/<int:result_id>", methods=["GET"])
@auth.login_required
def get_result(result_id):
    """Return a single result by ID."""
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM analysis_results WHERE id = ?", (result_id,)).fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    abort(404, description="Result not found")

# --- Error handlers ---
@app.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e)), 404

@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error="Unauthorized"), 401

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal server error"), 500

# --- Main ---
if __name__ == "__main__":
    cert_file = os.getenv("SSL_CERT", "dev_cert.pem")
    key_file = os.getenv("SSL_KEY", "dev_key.pem")

    context = (cert_file, key_file) if os.path.exists(cert_file) and os.path.exists(key_file) else None

    print(f"[*] Starting SentinelLS Dashboard at https://{APP_HOST}:{APP_PORT}")
    print(f"[*] Using DB: {DB_FILE}")
    print(f"[*] Debug mode: {DEBUG_MODE}")
    app.run(host=APP_HOST, port=APP_PORT, ssl_context=context, debug=DEBUG_MODE)
