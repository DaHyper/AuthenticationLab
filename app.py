from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import sqlite3
import os
import pyotp
import qrcode
import io
from webauthn import generate_registration_options, generate_authentication_options, options_to_json, verify_registration_response, verify_authentication_response
import requests

# Load environment variables
load_dotenv()

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'devkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_TYPE"] = "filesystem"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
Session(app)

RP_ID = "authenticationlab.dahyper.org"  # your domain
RP_NAME = "AuthenticationLab"
ORIGIN = "https://authenticationlab.dahyper.org"

user_credentials = {}
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

# --- User model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)
github = oauth.register(
    name='github',
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)
microsoft = oauth.register(
    name='microsoft',
    client_id=os.getenv("MICROSOFT_CLIENT_ID"),
    client_secret=os.getenv("MICROSOFT_CLIENT_SECRET"),
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    api_base_url='https://graph.microsoft.com/v1.0/',
    client_kwargs={'scope': 'User.Read openid email profile'},
)
discord = oauth.register(
    name='discord',
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/api/',
    client_kwargs={'scope': 'identify email'},
)
apple = oauth.register(
    name='apple',
    client_id=os.getenv("APPLE_CLIENT_ID"),
    client_secret=os.getenv("APPLE_CLIENT_SECRET"),
    access_token_url='https://appleid.apple.com/auth/token',
    authorize_url='https://appleid.apple.com/auth/authorize',
    api_base_url='https://appleid.apple.com',
    client_kwargs={'scope': 'name email', 'response_mode': 'form_post'},
)
facebook = oauth.register(
    name='facebook',
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/v18.0/',
    client_kwargs={'scope': 'email public_profile'},
)

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
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)


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

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="AuthLab Demo")
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

    otp_uri = pyotp.totp.TOTP(user[3]).provisioning_uri(name=username, issuer_name="AuthLab Demo")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    user_info = google.userinfo()

    email = user_info.get("email")
    name = user_info.get("name", email.split("@")[0] if email else "Unknown")

    # Try to find existing user
    user = User.query.filter_by(username=email).first()
    if not user:
        user = User(username=email, password_hash="GOOGLE_OAUTH", mfa_enabled=False)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session["user"] = email
    flash("Logged in with Google!", "success")
    return redirect(url_for("dashboard"))

@app.route("/login/github")
def login_github():
    redirect_uri = url_for("github_callback", _external=True, _scheme="https")
    return github.authorize_redirect(redirect_uri)

@app.route("/auth/github/callback")
def github_callback():
    token = github.authorize_access_token()
    user_info = github.get("user").json()
    email = user_info.get("email")

    if not email:
        emails = github.get("user/emails").json()
        email = next((e["email"] for e in emails if e.get("primary")), None)

    name = user_info.get("name", email.split("@")[0] if email else "GitHubUser")

    user = User.query.filter_by(username=email).first()
    if not user:
        user = User(username=email, password_hash="GITHUB_OAUTH", mfa_enabled=False)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"Logged in with GitHub as {name}", "success")
    return redirect(url_for("dashboard"))

@app.route("/login/microsoft")
def login_microsoft():
    redirect_uri = url_for("microsoft_callback", _external=True, _scheme="https")
    return microsoft.authorize_redirect(redirect_uri)

@app.route("/auth/microsoft/callback")
def microsoft_callback():
    token = microsoft.authorize_access_token()
    user_info = microsoft.get("me").json()
    email = user_info.get("mail") or user_info.get("userPrincipalName")
    name = user_info.get("displayName", email.split("@")[0] if email else "MicrosoftUser")

    user = User.query.filter_by(username=email).first()
    if not user:
        user = User(username=email, password_hash="MICROSOFT_OAUTH", mfa_enabled=False)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"Logged in with Microsoft as {name}", "success")
    return redirect(url_for("dashboard"))


@app.route("/login/discord")
def login_discord():
    redirect_uri = url_for("discord_callback", _external=True, _scheme="https")
    return discord.authorize_redirect(redirect_uri)

@app.route("/auth/discord/callback")
def discord_callback():
    try:
        token = discord.authorize_access_token()
        if not token:
            flash("Discord authorization failed (no token).", "danger")
            return redirect(url_for("login"))

        print("DISCORD TOKEN:", token)

        headers = {"Authorization": f"Bearer {token['access_token']}"}
        resp = requests.get("https://discord.com/api/users/@me", headers=headers)

        # --- DEBUG: show response details ---
        print("DISCORD RESPONSE STATUS:", resp.status_code)
        print("DISCORD RESPONSE TEXT:", resp.text[:500])  # first 500 chars

        if resp.status_code != 200:
            flash(f"Discord API error: {resp.status_code}", "danger")
            return redirect(url_for("login"))

        user_info = resp.json()

        email = user_info.get("email", f"{user_info['id']}@discord")
        name = user_info.get("username", "DiscordUser")

        user = User.query.filter_by(username=email).first()
        if not user:
            user = User(username=email, password_hash="DISCORD_OAUTH", mfa_enabled=False)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash(f"Logged in with Discord as {name}", "success")
        return redirect(url_for("dashboard"))

    except Exception as e:
        print("DISCORD CALLBACK ERROR:", e)
        flash(f"Discord login failed: {e}", "danger")
        return redirect(url_for("login"))

@app.route("/login/apple")
def login_apple():
    redirect_uri = url_for("apple_callback", _external=True, _scheme="https")
    return apple.authorize_redirect(redirect_uri)

@app.route("/auth/apple/callback", methods=["GET", "POST"])
def apple_callback():
    token = apple.authorize_access_token()
    # Apple returns limited info (usually just email)
    user_info = token.get("userinfo") or {}
    email = user_info.get("email", "unknown@apple.com")
    name = user_info.get("name", email.split("@")[0])

    user = User.query.filter_by(username=email).first()
    if not user:
        user = User(username=email, password_hash="APPLE_OAUTH", mfa_enabled=False)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"Logged in with Apple as {name}", "success")
    return redirect(url_for("dashboard"))

@app.route("/login/facebook")
def login_facebook():
    redirect_uri = url_for("facebook_callback", _external=True, _scheme="https")
    return facebook.authorize_redirect(redirect_uri)

@app.route("/auth/facebook/callback")
def facebook_callback():
    token = facebook.authorize_access_token()
    user_info = facebook.get("me?fields=id,name,email").json()
    email = user_info.get("email")
    name = user_info.get("name", email.split("@")[0] if email else "FacebookUser")

    user = User.query.filter_by(username=email).first()
    if not user:
        user = User(username=email, password_hash="FACEBOOK_OAUTH", mfa_enabled=False)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"Logged in with Facebook as {name}", "success")
    return redirect(url_for("dashboard"))

@app.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    data = request.json
    try:
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=session["authentication_options"]["challenge"],
            expected_rp_id="authenticationlab.dahyper.org",
            expected_origin="https://authenticationlab.dahyper.org",
        )
        session["user"] = verification.credential_id
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "failed", "reason": str(e)}), 400


@app.route("/webauthn/register/begin", methods=["POST"])
def webauthn_register_begin():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Missing email"}), 400

    options = generate_registration_options(
        rp_name=RP_NAME,
        user_id=email.encode("utf-8"),
        user_name=email,
    )
    session["registration_options"] = options.model_dump()
    return jsonify(options_to_json(options))


@app.route("/webauthn/register/complete", methods=["POST"])
def webauthn_register_complete():
    data = request.json
    try:
        verification = verify_registration_response(
            credential=data,
            expected_challenge=session["registration_options"]["challenge"],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
        email = verification.credential.user_handle.decode()
        user_credentials[email] = verification.credential
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "failed", "reason": str(e)}), 400


@app.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    email = request.json.get("email")
    options = generate_authentication_options()
    session["authentication_options"] = options.model_dump()
    return jsonify(options_to_json(options))


@app.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    data = request.json
    try:
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=session["authentication_options"]["challenge"],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
        # You can now log the user in
        email = verification.credential.user_handle.decode()
        user = User.query.filter_by(username=email).first()
        if user:
            login_user(user)
            return jsonify({"status": "ok"})
        else:
            flash("No account linked to this passkey.", "danger")
            return jsonify({"status": "failed"}), 401
    except Exception as e:
        return jsonify({"status": "failed", "reason": str(e)}), 400


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
