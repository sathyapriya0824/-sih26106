"""
SIH26106 - Sentinel Trace
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence

Backend:
- Secure session authentication
- Role-based access control
- Password hashing
- Protected forensic APIs
"""

import os
import json
import sqlite3
import uuid
from datetime import datetime, timedelta

from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    send_file,
    abort,
    session,
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from analyzer import analyze_raw_email
from report import build_pdf_report


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")
DB_PATH = os.path.join(BASE_DIR, "cases.db")


# --------------------------------------------------------------------------
# Flask App
# --------------------------------------------------------------------------

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path=""
)

# IMPORTANT:
# For production, put a strong random value in the environment variable
# SENTINEL_SECRET_KEY instead of using the fallback.
app.secret_key = os.environ.get(
    "SENTINEL_SECRET_KEY",
    "CHANGE_THIS_SECRET_BEFORE_PRODUCTION_9f8a7c6d"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # Change to True when deployed with HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

CORS(app, supports_credentials=True)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = db()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Existing forensic cases table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            created_at TEXT,
            subject TEXT,
            sender TEXT,
            score INTEGER,
            risk_level TEXT,
            analysis_json TEXT
        )
    """)

    conn.commit()

    # --------------------------------------------------------------
    # Demo accounts
    # --------------------------------------------------------------
    # Passwords are HASHED before being stored in the database.
    #
    # These are prototype/demo accounts.
    # For production, create users through an admin interface and
    # store secrets outside source code.
    # --------------------------------------------------------------

    demo_users = [
        ("admin", "SentinelAdmin@2026", "admin"),
        ("analyst", "Analyst@2026", "analyst"),
        ("investigator", "Investigator@2026", "investigator"),
        ("user", "User@2026", "user"),
    ]

    for username, password, role in demo_users:

        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if not existing:

            password_hash = generate_password_hash(
                password,
                method="scrypt"
            )

            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    role,
                    datetime.utcnow().isoformat()
                )
            )

    conn.commit()
    conn.close()


init_db()


# --------------------------------------------------------------------------
# Authentication Helpers
# --------------------------------------------------------------------------

def current_user():
    """
    Return logged-in user information from the server-side session.
    """

    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = db()

    user = conn.execute(
        """
        SELECT id, username, role
        FROM users
        WHERE id=?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:
        session.clear()
        return None

    return dict(user)


def login_required():
    """
    Require an authenticated user.
    """

    user = current_user()

    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401

    return user


def role_required(*allowed_roles):
    """
    Require authentication + specific role.
    """

    user = current_user()

    if not user:
        return None, (
            jsonify({
                "error": "Authentication required"
            }),
            401
        )

    if user["role"] not in allowed_roles:
        return None, (
            jsonify({
                "error": "Access denied for this role"
            }),
            403
        )

    return user, None


# --------------------------------------------------------------------------
# Frontend
# --------------------------------------------------------------------------

@app.route("/")
def index():

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/<path:path>")
def static_files(path):

    full = os.path.join(
        FRONTEND_DIR,
        path
    )

    if os.path.isfile(full):
        return send_from_directory(
            FRONTEND_DIR,
            path
        )

    abort(404)


# --------------------------------------------------------------------------
# AUTH API
# --------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():

    payload = request.get_json(silent=True) or {}

    username = str(
        payload.get("username", "")
    ).strip()

    password = str(
        payload.get("password", "")
    )

    if not username or not password:

        return jsonify({
            "error": "Username and password are required"
        }), 400

    conn = db()

    user = conn.execute(
        """
        SELECT id, username, password_hash, role
        FROM users
        WHERE username=?
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user:

        return jsonify({
            "error": "Invalid username or password"
        }), 401

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        return jsonify({
            "error": "Invalid username or password"
        }), 401

    # Server-side session
    session.clear()

    session.permanent = True

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return jsonify({
        "success": True,
        "username": user["username"],
        "role": user["role"]
    })


@app.route("/api/me", methods=["GET"])
def api_me():

    user = current_user()

    if not user:

        return jsonify({
            "authenticated": False
        }), 401

    return jsonify({
        "authenticated": True,
        "username": user["username"],
        "role": user["role"]
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():

    session.clear()

    return jsonify({
        "success": True
    })


# --------------------------------------------------------------------------
# EMAIL ANALYSIS
# --------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    user, error = role_required(
        "user",
        "analyst",
        "investigator",
        "admin"
    )

    if error:
        return error

    raw_bytes = None

    if (
        "file" in request.files
        and request.files["file"].filename
    ):

        raw_bytes = request.files["file"].read()

    else:

        payload = request.get_json(
            silent=True
        ) or {}

        raw_text = (
            payload.get("raw_text")
            or request.form.get("raw_text")
        )

        if raw_text:

            raw_bytes = raw_text.encode(
                "utf-8",
                errors="replace"
            )

    if not raw_bytes:

        return jsonify({
            "error":
            "No email content supplied. "
            "Upload a .eml file or paste raw source."
        }), 400

    try:

        analysis = analyze_raw_email(
            raw_bytes
        )

    except Exception as e:

        return jsonify({
            "error":
            f"Failed to parse email: {e}"
        }), 422

    case_id = str(
        uuid.uuid4()
    )[:8]

    conn = db()

    conn.execute(
        """
        INSERT INTO cases
        (
            id,
            created_at,
            subject,
            sender,
            score,
            risk_level,
            analysis_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            datetime.utcnow().isoformat(),
            analysis["summary"].get("subject"),
            analysis["summary"].get("from"),
            analysis["threat"]["score"],
            analysis["threat"]["risk_level"],
            json.dumps(analysis),
        ),
    )

    conn.commit()
    conn.close()

    analysis["case_id"] = case_id

    return jsonify(analysis)


# --------------------------------------------------------------------------
# CASE HISTORY
# --------------------------------------------------------------------------

@app.route("/api/history", methods=["GET"])
def api_history():

    user, error = role_required(
        "analyst",
        "investigator",
        "admin"
    )

    if error:
        return error

    conn = db()

    rows = conn.execute(
        """
        SELECT
            id,
            created_at,
            subject,
            sender,
            score,
            risk_level
        FROM cases
        ORDER BY created_at DESC
        LIMIT 50
        """
    ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


# --------------------------------------------------------------------------
# SINGLE CASE
# --------------------------------------------------------------------------

@app.route(
    "/api/case/<case_id>",
    methods=["GET"]
)
def api_case(case_id):

    user, error = role_required(
        "analyst",
        "investigator",
        "admin"
    )

    if error:
        return error

    conn = db()

    row = conn.execute(
        """
        SELECT analysis_json
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    ).fetchone()

    conn.close()

    if not row:

        return jsonify({
            "error": "case not found"
        }), 404

    return jsonify(
        json.loads(
            row["analysis_json"]
        )
    )


# --------------------------------------------------------------------------
# FORENSIC REPORT
# --------------------------------------------------------------------------

@app.route(
    "/api/report/<case_id>",
    methods=["GET"]
)
def api_report(case_id):

    user, error = role_required(
        "analyst",
        "investigator",
        "admin"
    )

    if error:
        return error

    conn = db()

    row = conn.execute(
        """
        SELECT analysis_json
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    ).fetchone()

    conn.close()

    if not row:

        return jsonify({
            "error": "case not found"
        }), 404

    analysis = json.loads(
        row["analysis_json"]
    )

    pdf_buf = build_pdf_report(
        case_id,
        analysis
    )

    return send_file(
        pdf_buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"forensic_report_{case_id}.pdf",
    )


# --------------------------------------------------------------------------
# RUN
# --------------------------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )