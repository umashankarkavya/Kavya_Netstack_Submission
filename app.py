import hashlib
import os
import re
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from functools import wraps
from pathlib import Path

import bcrypt
from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.environ.get("NESTACK_DB_PATH", str(BASE_DIR / "records.db"))
).resolve()

SESSION_SECONDS = 8 * 60 * 60
MAX_LOGIN_FAILURES = 5
LOCK_SECONDS = 15 * 60

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(connect_db()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK(role IN ('user', 'admin')),
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
        """)
        db.commit()


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_db():
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.errorhandler(400)
def bad_request(error):
    return jsonify(error="Invalid request"), 400


@app.errorhandler(413)
def too_large(error):
    return jsonify(error="Request body too large"), 400


def json_body(required_fields):
    if not request.is_json:
        return None, (jsonify(error="Content-Type must be application/json"), 400)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None, (jsonify(error="A JSON object is required"), 400)

    # Reject unexpected fields, including attempts to submit a role.
    if set(data.keys()) != set(required_fields):
        return None, (jsonify(error="Unexpected or missing fields"), 400)

    return data, None


def username_key(value):
    return value.strip().lower()


def valid_credentials(data):
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return False

    if not USERNAME_RE.fullmatch(username):
        return False

    if not 12 <= len(password) <= 72:
        return False

    # bcrypt has a 72-byte input limit.
    if len(password.encode("utf-8")) > 72:
        return False

    return True


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_user():
    header = request.headers.get("Authorization", "")
    scheme, separator, token = header.partition(" ")

    if scheme.lower() != "bearer" or not separator or not token:
        return None

    if len(token) > 200:
        return None

    db = get_db()
    now = int(time.time())

    session = db.execute("""
        SELECT users.id, users.username, users.role
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
          AND sessions.expires_at > ?
    """, (token_digest(token), now)).fetchone()

    return session


def require_auth(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        user = current_user()

        if user is None:
            return jsonify(error="Authentication required"), 401

        g.current_user = user
        return handler(*args, **kwargs)

    return wrapper


@app.get("/")
def home():
    return jsonify(
        message="Nestack Secure Records API",
        status="running"
    )


@app.post("/register")
def register():
    data, error = json_body({"username", "password"})
    if error:
        return error

    if not valid_credentials(data):
        return jsonify(
            error="Username must be 3-64 allowed characters; "
                  "password must be 12-72 characters"
        ), 400

    username = username_key(data["username"])
    password_hash = bcrypt.hashpw(
        data["password"].encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    )

    db = get_db()

    try:
        db.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, 'user')
        """, (username, password_hash))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="Username unavailable"), 409

    return jsonify(message="Account created"), 201


@app.post("/login")
def login():
    data, error = json_body({"username", "password"})
    if error:
        return error

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid credentials"), 400

    if len(username) > 64 or len(password) > 72:
        return jsonify(error="Invalid credentials"), 400

    username = username_key(username)
    db = get_db()
    now = int(time.time())

    # Check lockout before checking the password.
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        # Do a dummy bcrypt check to reduce username timing differences.
        bcrypt.checkpw(
            password.encode("utf-8"),
            bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=12))
        )
        return jsonify(error="Invalid credentials"), 401

    if user["locked_until"] > now:
        return jsonify(error="Too many failed attempts; try again later"), 429

    password_ok = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"]
    )

    if not password_ok:
        failures = user["failed_attempts"] + 1

        if failures >= MAX_LOGIN_FAILURES:
            db.execute("""
                UPDATE users
                SET failed_attempts = 0, locked_until = ?
                WHERE id = ?
            """, (now + LOCK_SECONDS, user["id"]))
            db.commit()
            return jsonify(
                error="Too many failed attempts; try again later"
            ), 429

        db.execute("""
            UPDATE users SET failed_attempts = ? WHERE id = ?
        """, (failures, user["id"]))
        db.commit()
        return jsonify(error="Invalid credentials"), 401

    db.execute("""
        UPDATE users
        SET failed_attempts = 0, locked_until = 0
        WHERE id = ?
    """, (user["id"],))

    # Store only a hash of the random session token in the database.
    token = secrets.token_urlsafe(32)
    db.execute("""
        INSERT INTO sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (token_digest(token), user["id"], now + SESSION_SECONDS))

    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    db.commit()

    return jsonify(
        access_token=token,
        token_type="Bearer",
        expires_in=SESSION_SECONDS
    ), 200


@app.post("/records")
@require_auth
def create_record():
    data, error = json_body({"title", "body"})
    if error:
        return error

    title = data.get("title")
    body = data.get("body")

    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="Title and body must be strings"), 400

    if not title.strip() or len(title) > 200:
        return jsonify(error="Title must be 1-200 characters"), 400

    if not body.strip() or len(body) > 10000:
        return jsonify(error="Body must be 1-10000 characters"), 400

    db = get_db()
    cursor = db.execute("""
        INSERT INTO records (owner_id, title, body, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        g.current_user["id"],
        title.strip(),
        body,
        int(time.time())
    ))
    db.commit()

    return jsonify(id=cursor.lastrowid), 201
@app.get("/records")
@require_auth
def list_records():
    db = get_db()
    user = g.current_user

    if user["role"] == "admin":
        records = db.execute("""
            SELECT id, owner_id, title, body, created_at
            FROM records
            ORDER BY id DESC
        """).fetchall()
    else:
        records = db.execute("""
            SELECT id, owner_id, title, body, created_at
            FROM records
            WHERE owner_id = ?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

    return jsonify([dict(record) for record in records]), 200

@app.get("/records/<int:record_id>")
@require_auth
def get_record(record_id):
    if record_id <= 0:
        return jsonify(error="Record not found"), 404

    db = get_db()
    user = g.current_user

    if user["role"] == "admin":
        record = db.execute("""
            SELECT id, owner_id, title, body, created_at
            FROM records WHERE id = ?
        """, (record_id,)).fetchone()
    else:
        # Enforce ownership inside the SQL query itself.
        record = db.execute("""
            SELECT id, owner_id, title, body, created_at
            FROM records
            WHERE id = ? AND owner_id = ?
        """, (record_id, user["id"])).fetchone()

    if record is None:
        return jsonify(error="Record not found"), 404

    return jsonify(dict(record)), 200


def make_admin(username):
    username = username_key(username)

    with closing(connect_db()) as db:
        cursor = db.execute(
            "UPDATE users SET role = 'admin' WHERE username = ?",
            (username,)
        )
        db.commit()

        if cursor.rowcount != 1:
            print("User not found. Register the account first.")
            return 1

    print("Admin role assigned to:", username)
    return 0


if __name__ == "__main__":
    init_db()

    # Admin provisioning is an operator command, not a public API route.
    if len(sys.argv) == 3 and sys.argv[1] == "make-admin":
        raise SystemExit(make_admin(sys.argv[2]))

    if len(sys.argv) != 1:
        raise SystemExit("Usage: python app.py [make-admin USERNAME]")

    app.run(host="127.0.0.1", port=5000, debug=False)