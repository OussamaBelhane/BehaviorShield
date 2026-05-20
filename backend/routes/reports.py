"""backend/routes/reports.py - PDF report generation via WeasyPrint"""

import io
import pathlib
import os
import sys
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, send_file, current_app, render_template_string
from database.db import get_connection

# 1. WeasyPrint availability check (and Windows DLL path fix)
if sys.platform == 'win32':
    gtk_path = r"C:\Program Files\GTK3-Runtime Win64\bin"
    if os.path.exists(gtk_path):
        # Add to PATH for older python or certain library loaders
        os.environ['PATH'] = gtk_path + os.pathsep + os.environ.get('PATH', '')
        # Python 3.8+ requires explicit DLL directory addition
        if hasattr(os, 'add_dll_directory'):
            try:
                os.add_dll_directory(gtk_path)
            except Exception:
                pass

try:
    from weasyprint import HTML
    _WEASYPRINT_AVAILABLE = (HTML is not None)
except Exception:
    HTML = None
    _WEASYPRINT_AVAILABLE = False

reports_bp = Blueprint("reports", __name__)

_TEMPLATE_PATH = pathlib.Path(__file__).parent.parent.parent / "reports" / "report_template.html"


@reports_bp.route("/reports/generate")
def generate_report():
    if not _WEASYPRINT_AVAILABLE:
        return jsonify({
            "error": "WeasyPrint library is not installed or missing system dependencies (GTK/GObject). "
                     "Please install it with: pip install weasyprint"
        }), 503

    if not _TEMPLATE_PATH.exists():
        return jsonify({
            "error": f"Report template not found at {_TEMPLATE_PATH}. "
                     "Please ensure the 'reports/report_template.html' file exists."
        }), 500
    db       = current_app.config["DB_PATH"]
    from_ts  = request.args.get("from", "")
    to_ts    = request.args.get("to",   "")

    # -- Fetch data ------------------------------------------------
    conn = get_connection(db)
    try:
        # Events (Filtered by whitelist)
        events_q = """
            SELECT e.* 
            FROM events e
            LEFT JOIN processes p ON p.pid = e.pid
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256))
            )
            WHERE w.id IS NULL
            ORDER BY e.timestamp DESC 
            LIMIT 500
        """
        events   = [dict(r) for r in conn.execute(events_q).fetchall()]

        # Alerts (Filtered by whitelist)
        alerts_q = """
            SELECT a.* 
            FROM alerts a
            LEFT JOIN processes p ON p.pid = a.pid
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256))
            )
            WHERE w.id IS NULL
            ORDER BY a.timestamp DESC 
            LIMIT 200
        """
        alerts   = [dict(r) for r in conn.execute(alerts_q).fetchall()]

        # Quarantine
        quar_q = "SELECT * FROM quarantine ORDER BY quarantined_at DESC"
        quarantine = [dict(r) for r in conn.execute(quar_q).fetchall()]

        # Stats
        total_events   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        kills          = conn.execute("SELECT COUNT(*) FROM processes WHERE status='KILLED'").fetchone()[0]
        whitelist_count = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]

    finally:
        conn.close()

    # -- Render HTML template --------------------------------------
    try:
        template_html = _TEMPLATE_PATH.read_text(encoding="utf-8")
        rendered = render_template_string(
            template_html,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            events=events,
            alerts=alerts,
            quarantine=quarantine,
            total_events=total_events,
            total_alerts=total_alerts,
            kills=kills,
            whitelist_count=whitelist_count,
            from_ts=from_ts or "All time",
            to_ts=to_ts or "Now",
        )
    except Exception as e:
        current_app.logger.error(f"Template rendering failed: {e}")
        return jsonify({"error": f"Template rendering failed: {e}"}), 500

    # -- Convert to PDF --------------------------------------------
    try:
        pdf_bytes = HTML(string=rendered, base_url=None).write_pdf()
    except Exception as exc:
        current_app.logger.error(f"PDF conversion failed: {exc}")
        return jsonify({"error": f"PDF conversion failed: {exc}"}), 500

    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    filename = f"BehaviorShield_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@reports_bp.route("/reports")
def list_reports():
    """Return a list of generated report files."""
    # Placeholder: currently we don't store PDFs on disk, they are generated on-the-fly.
    # In the future, we could scan a 'reports' directory or a DB table.
    return jsonify({"reports": []})
