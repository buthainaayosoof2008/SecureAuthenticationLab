
import os
import re
import sqlite3
from pathlib import Path
from datetime import timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# ==================================================
# 1. APPLICATION CONFIGURATION
# ==================================================

app = Flask(__name__)

secret_key = os.environ.get("APP_SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "APP_SECRET_KEY is missing. "
        "Set it in PowerShell before starting the application."
    )

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "0") == "1"
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=False,
    MAX_CONTENT_LENGTH=16 * 1024
)

# Enable CSRF protection for POST requests.
csrf = CSRFProtect(app)


# ==================================================
# 2. DATABASE CONFIGURATION
# ==================================================

DATABASE = Path(__file__).resolve().parent / "users.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)


# ==================================================
# 3. LOGIN RATE LIMITING
# ==================================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)


# ==================================================
# 4. VALIDATION AND DATABASE HELPERS
# ==================================================

def validate_username(username):
    return bool(
        re.fullmatch(r"[A-Za-z0-9_]{3,30}", username)
    )


def get_user(username):
    with get_db() as connection:
        return connection.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()


# ==================================================
# 5. HOME PAGE
# ==================================================

@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">
        <title>SecureAuth Lab</title>
        <style>
            body {
                margin: 0;
                padding: 70px 8%;
                font-family: Arial, sans-serif;
                background: #0b1020;
                color: #f1f5f9;
            }

            main {
                max-width: 760px;
                padding: 36px;
                background: #121a2e;
                border: 1px solid #29334b;
                border-radius: 18px;
            }

            h1 span, a {
                color: #a78bfa;
            }

            p {
                color: #a8b2c8;
                line-height: 1.8;
            }

            a {
                margin-right: 22px;
            }
        </style>
    </head>
    <body>
        <main>
            <h1>Secure<span>Auth</span> Lab</h1>
            <p>A practical cybersecurity authentication project.</p>
            <p>
                Secure password storage, CSRF protection,
                login rate limiting and session management.
            </p>
            <a href="/register">Create Account</a>
            <a href="/login">Sign In</a>
        </main>
    </body>
    </html>
    """


# ==================================================
# 6. USER REGISTRATION
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not validate_username(username):
        flash(
            "Use 3–30 characters: letters, numbers, or underscores.",
            "error"
        )
        return redirect(url_for("register"))

    if not 12 <= len(password) <= 128:
        flash(
            "Password must be between 12 and 128 characters.",
            "error"
        )
        return redirect(url_for("register"))

    # Hash the password before storing it.
    password_hash = generate_password_hash(password)

    try:
        with get_db() as connection:
            connection.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash)
            )

    except sqlite3.IntegrityError:
        flash(
            "Unable to create this account. Try a different username.",
            "error"
        )
        return redirect(url_for("register"))

    flash(
        "Account created successfully. You can now sign in.",
        "success"
    )

    return redirect(url_for("login"))


# ==================================================
# 7. USER LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = get_user(username) if validate_username(username) else None

    if user is None:
        # Return a generic error so usernames are not revealed.
        check_password_hash(
            generate_password_hash(
                "dummy-password-not-for-login"
            ),
            password
        )

        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    if not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    # Clear any previous session data after successful authentication.
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    return redirect(url_for("dashboard"))


# ==================================================
# 8. PROTECTED DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Please sign in to continue.", "error")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session.get("username", "User")
    )


# ==================================================
# 9. LOGOUT
# ==================================================

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")

    return redirect(url_for("login"))


# ==================================================
# 10. ERROR HANDLERS
# ==================================================

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return (
        "Too many login attempts. Please wait before trying again.",
        429
    )


@app.errorhandler(400)
def bad_request(error):
    return (
        "The request could not be verified. "
        "Refresh the page and try again.",
        400
    )


# ==================================================
# 11. START APPLICATION
# ==================================================

if __name__ == "__main__":
    initialize_database()

    # Debug mode is disabled.
    app.run(debug=False)
