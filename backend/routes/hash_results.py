"""
backend/routes/hash_results.py
-------------------------------
API endpoints for hash scan results.

GET /api/hash-results        -> last 50 scanned hashes
GET /api/hash-results/<sha>  -> single hash scan result
"""

from flask import Blueprint, jsonify, current_app
from database.db import get_connection

hash_results_bp = Blueprint("hash_results", __name__)


@hash_results_bp.route("/hash-results")
def get_hash_results():
    """Return last 50 scanned hashes with result + source + vt_score."""
    conn = get_connection(current_app.config["DB_PATH"])
    try:
        rows = conn.execute(
            """
            SELECT id, sha256, exe_path, result, source, vt_score, scanned_at
            FROM hash_cache
            ORDER BY scanned_at DESC
            LIMIT 50
            """
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@hash_results_bp.route("/hash-results/<sha256>")
def get_hash_result(sha256: str):
    """Return single hash scan result."""
    conn = get_connection(current_app.config["DB_PATH"])
    try:
        row = conn.execute(
            "SELECT id, sha256, exe_path, result, source, vt_score, scanned_at "
            "FROM hash_cache WHERE sha256 = ?",
            (sha256.lower(),),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Hash not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()
