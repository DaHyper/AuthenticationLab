from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import pyotp
import qrcode
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

DB_FILE = "users.db"

# --- Database setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            mfa_secret TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Helpers ---
def get_user(username):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()
    return user


# --- Routes ---
@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        code = request.form.get("code")  # optional MFA code

        user = get_user(username)
        if user and check_password_hash(user[2], password):
            mfa_secret = user[3]

            # If user has MFA enabled, check code
            if mfa_secret:
                if not code:
                    flash("MFA code required for this account.", "warning")
                    return render_template("login.html", username=username, require_mfa=True)

                totp = pyotp.TOTP(mfa_secret)
                if not totp.verify(code):
                    flash("Invalid MFA code.", "danger")
                    return render_template("login.html", username=username, require_mfa=True)

            # Success
            session["user"] = username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])


@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user(session["user"])
    mfa_enabled = bool(user[3])
    return render_template("settings.html", username=session["user"], mfa_enabled=mfa_enabled)


@app.route("/enable_mfa")
def enable_mfa():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    user = get_user(username)

    # Generate new secret if not existing
    if not user[3]:
        secret = pyotp.random_base32()
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("UPDATE users SET mfa_secret=? WHERE username=?", (secret, username))
        conn.commit()
        conn.close()
    else:
        secret = user[3]

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MultiAuth Demo")
    return render_template("enable_mfa.html", username=username, secret=secret, otp_uri=otp_uri)

@app.route("/disable_mfa", methods=["POST"])
def disable_mfa():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("UPDATE users SET mfa_secret=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()
    flash("MFA disabled successfully.", "info")
    return redirect(url_for("settings"))


@app.route("/qrcode")
def qrcode_image():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    user = get_user(username)
    if not user or not user[3]:
        flash("No MFA secret found.", "danger")
        return redirect(url_for("settings"))

    otp_uri = pyotp.totp.TOTP(user[3]).provisioning_uri(name=username, issuer_name="MultiAuth Demo")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
