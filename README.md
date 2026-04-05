# 📦 CoreSight Vault

A self-hosted IT documentation, asset management, and password vault platform designed for MSPs and IT professionals.

Built with Flask, CoreSight Vault provides a lightweight alternative to tools like IT Glue and Hudu — with full control, extensibility, and no per-user licensing.

---

## 🚀 Features

### 🔐 Authentication & Security
- User login system with password hashing
- Forced password change on first login
- Email-based user onboarding (welcome email + temp password)
- Password complexity enforcement
- Optional MFA support (TOTP ready)
- Audit logging for key actions

---

### 🏢 Organisation Management
- Multi-tenant organisation structure
- Scoped data per organisation
- Clean org dashboard view

---

### 🔍 Global Search
- Search across:
  - Passwords
  - Documents
  - Assets
  - Domains
- Works without needing to select an organisation first

---

### 🔑 Password Vault
- Secure password storage
- Masked fields with reveal
- Copy-to-clipboard functionality

---

### 📄 Documentation System
- Folder-based structure
- File uploads (PDF, images, docs)
- Breadcrumb navigation

---

### 🌐 Domain Management
- Domain tracking per organisation
- DNS lookup support:
  - A, MX, TXT, NS, DMARC

---

### 🖥️ Asset Management
- Device tracking (name, type, serial, user, location)
- Built for MSP environments

---

### 📊 Dashboard
- Per-organisation overview:
  - Assets
  - Documents
  - Passwords

---

## ⚙️ Tech Stack

- Python 3.12+
- Flask
- Flask-Login
- Flask-SQLAlchemy
- SQLite
- Bootstrap

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/coresight-vault.git
cd coresight-vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ Environment Variables

Create a `.env` file:

```
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///coresight.db
VAULT_KEY=your-encryption-key
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=you@example.com
MAIL_PASSWORD=yourpassword
MAIL_USE_TLS=True
MAIL_FROM=you@example.com
```

---

## 🗄️ Database Setup

```python
from app import app, db

with app.app_context():
    db.create_all()
```

---

## ▶️ Run

```bash
python app.py
```

---

## 👤 First User

```python
from app import app, db, User

with app.app_context():
    u = User(email="admin@local")
    u.set_password("TempPassword123!")
    u.is_super_admin = True
    u.must_change_password = True
    db.session.add(u)
    db.session.commit()
```

---

## 🔐 Security Notes

- Change SECRET_KEY
- Use strong VAULT_KEY
- Run behind HTTPS
- Restrict access (VPN/firewall)

---

## 📌 Roadmap

- API support
- Role permissions
- Backup integrations
- RMM integrations
- Client portal
- Reporting

---

## 💡 About

Built for real-world MSP usage by CoreSight IT.
