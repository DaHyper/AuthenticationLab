# AuthenticationLab
This project is a lightweight web application that demonstrates multiple authentication methods in a simple, visual way.  
When you log in successfully, you unlock a meme

This project is designed to show practical authentication and cybersecurity concepts without unnecessary complexity.

---

## ⚠️ **NOTE:**   ⚠️
Do not use this for a production deployment without additioonal hardening, I am **not** responsible for any incidents or damages by deploying this in your environment.

---

## 🚀 Overview

The app allows users to:
- Register and log in with a **username and password**
- Enable or disable **Multi-Factor Authentication (MFA)** using a TOTP code (e.g., Google Authenticator)
- Log in with optional **OAuth** providers (GitHub, Google, etc.)
- Experiment with **WebAuthn / Passkey** for passwordless authentication
- Access a **settings page** to manage MFA or change their password
- Log out securely (session/token invalidation)

After a successful login, users are redirected to a protected dashboard that shows a meme or simple confirmation page.

---

## 🧱 Project Structure
```
project/
├── app.py # Flask backend
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── dashboard.html
│ ├── settings.html
│ └── base.html
├── static/
│ └── meme.jpg # Or fetched from an API
├── requirements.txt
└── README.md
```


---

## ⚙️ How It Works

### 1. Registration
- Users create an account with a **username and password**.
- Passwords are hashed using **bcrypt** or **Argon2** before being stored in the database.
- A new user record is created in the database (e.g., SQLite).

### 2. Login
1. User enters their credentials.
2. The backend verifies the password hash.
3. If MFA is enabled, the app prompts for a 6-digit verification code.
4. Upon success:
   - A secure session is created.
   - The user is redirected to the protected dashboard.
   - The meme or confirmation image is displayed.

### 3. Multi-Factor Authentication (MFA)
- Users can enable MFA in the **Settings** page.
- The app generates a **TOTP secret** using a library such as `pyotp`.
- The secret is displayed as a **QR code**, scannable with Google Authenticator or similar apps.
- During login, users must provide both their password and current 6-digit code.
- MFA can be disabled later from settings.

### 4. OAuth Login (Optional)
- Users can log in with third-party providers such as **GitHub** or **Google**.
- The app uses **OAuth 2.0 / OpenID Connect** to authenticate via provider tokens.
- On first login, a local user account is created and linked.
- Tokens are verified and used only for authentication (not stored long-term).

### 5. WebAuthn / Passkey (Optional)
- Advanced users can register hardware-based credentials like **YubiKeys** or platform **passkeys**.
- Authentication is handled using the **WebAuthn API**.
- The app verifies signed challenges using stored public keys, providing passwordless login capability.

---

## 🔒 Security Features Demonstrated

| Feature | Concept |
|----------|----------|
| Password Hashing | bcrypt / Argon2 secure storage |
| Multi-Factor Auth | TOTP-based 2FA verification |
| OAuth | Federated identity and delegated authentication |
| WebAuthn / Passkeys | Passwordless authentication using public key crypto |
| Secure Sessions | Cookie flags (`HttpOnly`, `SameSite`, `Secure`) |
| Logout | Session invalidation and token revocation |
| Brute-Force Defense | Login rate limiting or account lockouts |
| CSRF Protection | Form tokens and secure request validation |

---

## 🧠 Learning Outcomes

By building or reviewing this app, you’ll gain hands-on understanding of:

- Secure password management and login logic  
- How MFA and TOTP work internally  
- The OAuth login flow and callback validation  
- The mechanics of WebAuthn and FIDO2 keys  
- How to protect sessions, tokens, and credentials  
- Common authentication vulnerabilities and mitigations  

---

## 🧰 Tech Stack

| Component | Technology |
|------------|-------------|
| Framework | Flask (Python) |
| Database | SQLite (simple and portable) |
| Auth Libraries | Flask-Login, Flask-Session, pyotp, Authlib |
| Optional WebAuthn | `webauthn` |
| Frontend | HTML + Tailwind CSS |
| Meme/Image | Static file or API (e.g., Reddit, Imgflip) |

---

## 🧪 Running the App

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the Flask app
flask run

# 3. Open in browser
http://localhost:3000
```

---


🔁 Example Usage Flow
1. Register a new account at /register
2. Log in with username and password
3. View the protected meme/dashboard page
4. Enable MFA in /settings and scan the QR code
4. Log out and test MFA login
6. (Optional) Try OAuth or WebAuthn login

🧱 Future Enhancements
- Password reset via email token
- Admin interface for monitoring login attempts
- Rate limiting for brute-force prevention
- Logging and audit trails
- API key or JWT-based auth layer
