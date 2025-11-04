from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from base64 import b64encode, b64decode
import sqlite3
import os
import pyotp
import qrcode
import io
from webauthn import generate_registration_options, generate_authentication_options, options_to_json, verify_registration_response, verify_authentication_response
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
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

class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    name = db.Column(db.String(100), default="My Passkey")
    
    user = db.relationship('User', backref=db.backref('webauthn_credentials', lazy=True))

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

        # Check if user already exists in SQLAlchemy
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.", "danger")
            return render_template("register.html")

        # Create new user in SQLAlchemy
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Also add to sqlite3 for backward compatibility
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()

        # Auto-login the user
        login_user(new_user)
        session["user"] = username
        flash("Registration successful! You are now logged in.", "success")
        return redirect(url_for("dashboard"))
    
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        code = request.form.get("code")  # optional MFA code

        user_data = get_user(username)
        if user_data and check_password_hash(user_data[2], password):
            mfa_secret = user_data[3]

            # If user has MFA enabled, check code
            if mfa_secret:
                if not code:
                    flash("MFA code required for this account.", "warning")
                    return render_template("login.html", username=username, require_mfa=True)

                totp = pyotp.TOTP(mfa_secret)
                if not totp.verify(code):
                    flash("Invalid MFA code.", "danger")
                    return render_template("login.html", username=username, require_mfa=True)

            user = User.query.filter_by(username=username).first()
            if user:
                login_user(user)
                session["user"] = username  # Keep for backward compatibility
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
@login_required
def settings():
    user = get_user(current_user.username)
    mfa_enabled = bool(user[3]) if user else False
    passkey_count = WebAuthnCredential.query.filter_by(user_id=current_user.id).count()
    return render_template("settings.html", username=session["user"], mfa_enabled=mfa_enabled, passkey_count=passkey_count)

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

@app.route("/webauthn/register/begin", methods=["POST"])
@login_required
def webauthn_register_begin():
    email = current_user.username
    
    # Get existing credentials to exclude them
    existing_creds = WebAuthnCredential.query.filter_by(user_id=current_user.id).all()
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in existing_creds
    ]
    
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=email.encode("utf-8"),
        user_name=email,
        exclude_credentials=exclude_credentials if exclude_credentials else None
    )
    
    # Store challenge in session for verification
    session["registration_challenge"] = b64encode(options.challenge).decode("utf-8")
    
    # Convert to JSON-serializable format
    publicKey = {
        "challenge": b64encode(options.challenge).decode("utf-8"),
        "rp": {"name": options.rp.name, "id": options.rp.id},
        "user": {
            "id": b64encode(options.user.id).decode("utf-8"),
            "name": options.user.name,
            "displayName": options.user.display_name
        },
        "pubKeyCredParams": [{"type": p.type, "alg": p.alg} for p in options.pub_key_cred_params],
        "timeout": options.timeout,
        "attestation": options.attestation,
        "authenticatorSelection": {
            "userVerification": options.authenticator_selection.user_verification
        } if options.authenticator_selection else {}
    }
    
    return jsonify({"publicKey": publicKey})

@app.route("/webauthn/register/complete", methods=["POST"])
@login_required
def webauthn_register_complete():
    data = request.json
    
    try:
        challenge = b64decode(session["registration_challenge"])

        verification = verify_registration_response(
            credential=data,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
        
        # Store the credential in the database
        new_credential = WebAuthnCredential(
            user_id=current_user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count
        )
        db.session.add(new_credential)
        db.session.commit()
        
        return jsonify({"status": "ok"})
    except Exception as e:
        print("Registration error:", e)
        return jsonify({"status": "failed", "reason": str(e)}), 400

@app.route("/webauthn/login/begin-usernameless", methods=["POST"])
def webauthn_login_begin_usernameless():
    """Start passkey login without requiring username"""
    try:
        options = generate_authentication_options(
            rp_id=RP_ID,
            user_verification="preferred"
        )

        session["authentication_challenge"] = b64encode(options.challenge).decode("utf-8")

        publicKey = {
            "challenge": b64encode(options.challenge).decode("utf-8"),
            "rpId": options.rp_id,
            "userVerification": options.user_verification,
            "timeout": options.timeout
        }

        return jsonify({"publicKey": publicKey})
    except Exception as e:
        print("Error starting usernameless login:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    username = request.json.get("username") or request.json.get("email")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    # Find user and their credentials
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get all credentials for this user
    credentials = WebAuthnCredential.query.filter_by(user_id=user.id).all()
    
    if not credentials:
        return jsonify({"error": "No passkeys registered for this account"}), 404
    
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in credentials
    ]
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification="preferred"
    )

    session["authentication_challenge"] = b64encode(options.challenge).decode("utf-8")
    session["webauthn_username"] = username

    publicKey = {
        "challenge": b64encode(options.challenge).decode("utf-8"),
        "rpId": options.rp_id,
        "allowCredentials": [
            {"type": "public-key", "id": b64encode(cred.id).decode("utf-8")}
            for cred in allow_credentials
        ],
        "userVerification": options.user_verification,
        "timeout": options.timeout
    }

    return jsonify({"publicKey": publicKey})

@app.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    data = request.json
    
    try:
        # Get challenge from session (stored as base64 string)
        if "authentication_challenge" not in session:
            return jsonify({"status": "failed", "reason": "No authentication challenge found. Please try again."}), 400
        
        challenge = b64decode(session["authentication_challenge"])
        
        # Decode credential_id to find the credential
        credential_id = b64decode(data["rawId"])
        
        # Find the credential
        credential_record = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if not credential_record:
            return jsonify({"status": "failed", "reason": "Credential not found"}), 404
        
        # Pass the credential data directly
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=credential_record.public_key,
            credential_current_sign_count=credential_record.sign_count
        )
        
        # Update sign count
        credential_record.sign_count = verification.new_sign_count
        db.session.commit()
        
        # Log the user in
        user = User.query.get(credential_record.user_id)
        login_user(user)
        session["user"] = user.username
        
        return jsonify({"status": "ok"})
        
    except Exception as e:
        print("Authentication error:", e)
        error_message = str(e)
    
        if "not allowed" in error_message.lower() or "timeout" in error_message.lower():
                error_message = "Passkey authentication was cancelled or timed out. Please try again."
        elif "credential" in error_message.lower():
                error_message = "This passkey is not registered with any account."
        elif "challenge" in error_message.lower():
                error_message = "Authentication session expired. Please try again."
            
        return jsonify({"status": "failed", "reason": error_message}), 400

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
