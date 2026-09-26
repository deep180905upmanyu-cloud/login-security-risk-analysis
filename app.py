import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USERNAME, DATABASE_PATH
from services.ai_security import analyze_login_activity

app = Flask(__name__)
app.config.from_object("config")


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_login_attempts_schema():
    conn = get_db_connection()
    columns = [column[1] for column in conn.execute("PRAGMA table_info(login_attempts)").fetchall()]

    if "failed_attempts" not in columns:
        conn.execute("ALTER TABLE login_attempts ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    if "risk_reason" not in columns:
        conn.execute("ALTER TABLE login_attempts ADD COLUMN risk_reason TEXT")
        conn.execute("UPDATE login_attempts SET risk_reason = reason WHERE reason IS NOT NULL AND risk_reason IS NULL")
    conn.commit()
    conn.close()


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            account_status TEXT NOT NULL DEFAULT 'ACTIVE',
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            email TEXT,
            ip_address TEXT,
            success INTEGER NOT NULL DEFAULT 0,
            attempt_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'NORMAL',
            failed_attempts INTEGER DEFAULT 0,
            risk_level TEXT,
            risk_reason TEXT,
            recommendation TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()
    conn.close()
    migrate_login_attempts_schema()
    seed_admin_user()


def seed_admin_user():
    conn = get_db_connection()
    existing_admin = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if existing_admin is None:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, failed_login_attempts, account_status, is_admin) VALUES (?, ?, ?, 0, 'ACTIVE', 1)",
            (ADMIN_USERNAME, ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD)),
        )
        conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_identifier(identifier):
    if not identifier:
        return None
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1",
        (identifier, identifier),
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def get_recent_attempts(user_id=None, limit=10):
    conn = get_db_connection()
    if user_id is not None:
        rows = conn.execute(
            "SELECT * FROM login_attempts WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM login_attempts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_filtered_attempts(filter_name="all", limit=100):
    conn = get_db_connection()
    allowed_filters = {
        "all": "SELECT * FROM login_attempts ORDER BY id DESC LIMIT ?",
        "successful": "SELECT * FROM login_attempts WHERE success = 1 ORDER BY id DESC LIMIT ?",
        "failed": "SELECT * FROM login_attempts WHERE success = 0 ORDER BY id DESC LIMIT ?",
        "suspicious": "SELECT * FROM login_attempts WHERE status = 'SUSPICIOUS' OR risk_level IN ('MEDIUM', 'HIGH') ORDER BY id DESC LIMIT ?",
    }
    query = allowed_filters.get(filter_name, allowed_filters["all"])
    rows = conn.execute(query, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_admin_summary():
    conn = get_db_connection()
    summary = {
        "total_users": conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"],
        "successful_logins": conn.execute(
            "SELECT COUNT(*) AS total FROM login_attempts WHERE success = 1"
        ).fetchone()["total"],
        "failed_logins": conn.execute(
            "SELECT COUNT(*) AS total FROM login_attempts WHERE success = 0"
        ).fetchone()["total"],
        "locked_accounts": conn.execute(
            "SELECT COUNT(*) AS total FROM users WHERE account_status = 'LOCKED'"
        ).fetchone()["total"],
        "suspicious_activities": conn.execute(
            "SELECT COUNT(*) AS total FROM login_attempts WHERE status = 'SUSPICIOUS' OR risk_level IN ('MEDIUM', 'HIGH')"
        ).fetchone()["total"],
    }
    conn.close()
    return summary


def record_login_attempt(
    user_id=None,
    username=None,
    email=None,
    ip_address=None,
    success=False,
    status="NORMAL",
    failed_attempts=0,
    risk_level=None,
    risk_reason=None,
    recommendation=None,
):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO login_attempts (user_id, username, email, ip_address, success, status, failed_attempts, risk_level, risk_reason, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            email,
            ip_address,
            1 if success else 0,
            status,
            failed_attempts,
            risk_level,
            risk_reason,
            recommendation,
        ),
    )
    conn.commit()
    conn.close()


def security_status_for(failed_attempts):
    if failed_attempts >= 5:
        return "LOCKED"
    if failed_attempts >= 3:
        return "SUSPICIOUS"
    return "ACTIVE"


def require_login(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def require_admin(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or not user.get("is_admin"):
            flash("You do not have permission to access the admin area.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password or not confirm_password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        conn = get_db_connection()
        existing_username = conn.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
        existing_email = conn.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()

        if existing_username:
            flash("This username is already registered.", "danger")
            conn.close()
            return render_template("register.html")

        if existing_email:
            flash("This email is already registered.", "danger")
            conn.close()
            return render_template("register.html")

        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, failed_login_attempts, account_status, is_admin) VALUES (?, ?, ?, 0, 'ACTIVE', 0)",
                (username, email, generate_password_hash(password)),
            )
            conn.commit()
            conn.close()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.Error:
            conn.close()
            flash("Registration failed. Please try again.", "danger")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter your username/email and password.", "danger")
            return render_template("login.html")

        user = get_user_by_identifier(identifier)

        if not user:
            record_login_attempt(
                username=identifier,
                email="",
                ip_address=request.remote_addr,
                success=False,
                status="NORMAL",
                failed_attempts=0,
                risk_level="LOW",
                risk_reason="Unknown username or email used during login.",
                recommendation="Double-check the entered username or email.",
            )
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html")

        if user["account_status"] == "LOCKED":
            record_login_attempt(
                user_id=user["id"],
                username=user["username"],
                email=user["email"],
                ip_address=request.remote_addr,
                success=False,
                status="LOCKED",
                failed_attempts=int(user["failed_login_attempts"] or 0),
                risk_level="HIGH",
                risk_reason="Account is temporarily locked after repeated failed attempts.",
                recommendation="Wait and try again later or contact the administrator.",
            )
            flash("This account is temporarily locked due to repeated failed login attempts.", "warning")
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            failed_attempts = int(user["failed_login_attempts"] or 0) + 1
            account_status = security_status_for(failed_attempts)
            ai_result = {
                "risk_level": "LOW",
                "reason": "Incorrect password entered.",
                "recommendation": "Review the account credentials and try again.",
            }

            if failed_attempts >= 3:
                ai_result = analyze_login_activity(
                    {
                        "username": user["username"],
                        "failed_attempts": failed_attempts,
                        "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "recent_login_attempts": get_recent_attempts(user_id=user["id"], limit=5),
                        "ip_address": request.remote_addr,
                        "account_status": account_status,
                    }
                )

            conn = get_db_connection()
            conn.execute(
                "UPDATE users SET failed_login_attempts = ?, account_status = ? WHERE id = ?",
                (failed_attempts, account_status, user["id"]),
            )
            conn.commit()
            conn.close()

            record_login_attempt(
                user_id=user["id"],
                username=user["username"],
                email=user["email"],
                ip_address=request.remote_addr,
                success=False,
                status=account_status,
                failed_attempts=failed_attempts,
                risk_level=ai_result.get("risk_level", "LOW"),
                risk_reason=ai_result.get("reason", "Incorrect password entered."),
                recommendation=ai_result.get("recommendation", "Check your credentials and try again."),
            )

            if failed_attempts >= 5:
                flash("Too many failed login attempts. Your account has been temporarily locked.", "danger")
            elif failed_attempts >= 3:
                flash("Suspicious login activity detected. Please check your credentials carefully.", "warning")
            else:
                flash("Invalid username/email or password.", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, account_status = 'ACTIVE', last_login = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
        )
        conn.commit()
        conn.close()

        record_login_attempt(
            user_id=user["id"],
            username=user["username"],
            email=user["email"],
            ip_address=request.remote_addr,
            success=True,
            status="SUCCESS",
            failed_attempts=0,
            risk_level="LOW",
            risk_reason="Successful login.",
            recommendation="Continue using the application normally.",
        )

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])

        flash("Login successful.", "success")
        if user["is_admin"]:
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@require_login
def dashboard():
    user = get_user_by_id(session["user_id"])
    recent_activity = get_recent_attempts(user_id=user["id"], limit=8)
    suspicious_activity = any(
        item.get("status") == "SUSPICIOUS" or item.get("risk_level") in ("MEDIUM", "HIGH")
        for item in recent_activity
    )
    return render_template(
        "dashboard.html",
        user=user,
        recent_activity=recent_activity,
        suspicious_activity=suspicious_activity,
    )


@app.route("/admin")
@require_admin
def admin():
    filter_name = request.args.get("filter", "all").lower()
    user = get_user_by_id(session["user_id"])
    summary = get_admin_summary()
    recent_attempts = get_filtered_attempts(filter_name=filter_name, limit=200)
    return render_template(
        "admin.html",
        user=user,
        summary=summary,
        recent_attempts=recent_attempts,
        current_filter=filter_name,
    )


@app.route("/admin/login-attempts")
@require_admin
def admin_login_attempts():
    return redirect(url_for("admin"))


@app.route("/admin/unlock/<int:user_id>", methods=["POST"])
@require_admin
def unlock_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin"))

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET account_status = 'ACTIVE', failed_login_attempts = 0 WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()

    flash("Account unlocked successfully.", "success")
    return redirect(url_for("admin"))


init_db()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"], host="0.0.0.0", port=5000)
