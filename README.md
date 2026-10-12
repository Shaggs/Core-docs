# 📦 CoreSight Vault

A self-hosted IT documentation, asset management, and password vault platform designed for MSPs and IT professionals.

Built with Flask, CoreSight Vault provides a lightweight alternative to tools like IT Glue and Hudu — with full control, extensibility, and no per-user licensing.

---

## 🚀 Features

### 🔐 Authentication & Security
- User login system with password hashing
- Forced password change on first login
- Email-based user onboarding: welcome email with a one-time set-password link (no passwords in email)
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
- Encrypted password storage (Fernet) with change history and rollback
- Masked fields with reveal, copy-to-clipboard, live TOTP codes
- CSV import (optional `folder` and `tags` columns)
- Password generator (length, symbols, skip look-alike characters; generated in your browser)
- Folders and tags: list grouped by folder, filter by folder or tag, search includes tags
- Rotation reminders ("change every 30/60/90/180/365 days"): overdue changes show on the Expiring page, badge and daily email

### 🔗 One-Time Password Sharing
- Share a password with a client via a link that expires (default 5 minutes) and can be revealed **once**
- Opening the link doesn't use it up (safe from email scanners); the client clicks **Reveal**, and the details auto-hide after 5 minutes
- Optionally email the link, add a message, see status (active / opened / expired / revoked) and revoke any active link
- Every create, reveal and revoke is audit-logged

### 🧩 Custom Record Types & Linked Records
- Admins define their own record types (licences, backup jobs, VPNs…) with text, long text, URL, number, date, dropdown, yes/no and encrypted password fields; presets included
- Link any record to any other in the same client (password ↔ asset ↔ document ↔ licence …), shown on both sides
- Custom records appear in global search and in the playbook PDF

### ⏰ Expiry Tracking & Alerts
- "Expiring soon" page across all clients: domains, asset warranties and any custom date field flagged for alerts
- Daily email digest (`python send_alerts.py` from cron); each item is reported once per window and re-arms after renewal
- Count badge on the sidebar and home page (amber = due within 30 days, red = already expired)

### 👥 Roles, Audit Log & Backups
- Roles: **Admin**, **Technician**, **Read-only** (read-only users can view and reveal, but can't create, edit, delete, share or export; those buttons are hidden for them)
- Audit log viewer with filters and CSV export (Admin → Audit log)
- Encrypted backups of the database + uploads (Admin → Backups, or `python backup.py create` / `restore`)

### 🛡️ Security
- CSRF protection on every form and background request, `SameSite=Lax` session cookies

### 🌓 Dark Theme
- Auto / Light / Dark toggle in the sidebar, remembered per browser

### 📘 Client Playbook (PDF Export)
- One PDF per client: cover, clickable contents, overview + onboarding, contacts, sites, network, domains, assets, documentation pages, uploaded files and passwords
- Uploaded PDFs/images can be appended as attachments
- Passwords are optional: admin-only, re-confirm your password, and the PDF is AES-256 encrypted
- Exports are audit-logged

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
- Flask, Flask-Login, Flask-SQLAlchemy
- SQLite (default)
- ReportLab + pypdf (playbook PDFs), cryptography (vault encryption)
- Bootstrap

---

## 🚀 Quick Start

```bash
git clone https://github.com/Shaggs/Core-docs.git
cd Core-docs
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python init_env.py               # generates .env with random SECRET_KEY + VAULT_KEY
python app.py                    # http://localhost:5001
```

The database is created automatically on first run. Sign in with **`admin@local` / `admin`**;
you'll be forced to choose a new password straight away.

> ⚠️ **Back up `.env`.** `VAULT_KEY` encrypts every stored password. If you lose or change it
> (or change `SECRET_KEY` when no `VAULT_KEY` is set), existing passwords cannot be decrypted.
> Set both **before** you add any data.

Need another admin, or locked out? `python add_admin.py you@example.com`

**Changing the vault key later** (e.g. after a staff member with server access leaves): stop the app, run
`python rotate_key.py`, then start the app again. It re-encrypts every stored secret with a new key, takes a backup
first, and keeps the old `.env` as `.env.before-rotation-<date>` (you need that old copy to restore backups made before the rotation).

---

## ⚙️ Configuration

Settings come from environment variables or a `.env` file (see `.env.example`).

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing. Required in production. |
| `VAULT_KEY` | Fernet key that encrypts stored secrets. `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `DATABASE_URL` | Defaults to `sqlite:///coresight.db` |
| `BEHIND_PROXY=1` | Set when behind nginx/Caddy/Traefik so share links use https and logs show real client IPs |
| `APP_BASE_URL` | Public URL, used for links in expiry-alert emails |
| `BACKUP_PASSPHRASE` / `BACKUP_KEEP` / `BACKUP_DIR` | Passphrase that encrypts backups (needed to restore), how many to keep (default 14), where they're stored |
| `COOKIE_SECURE=1` | Force the Secure flag on cookies (automatic with `BEHIND_PROXY=1`) |
| `UPLOAD_DIR` | Where uploaded documents are stored (default `./uploads`) |
| `TZ` | Local timezone, e.g. `Australia/Sydney` (used by the Docker scheduler) |
| `PLAYBOOK_MAX_ATTACH_MB` | Cap on attachments embedded in a playbook PDF (default 100) |
| `PLAYBOOK_FONT_DIR` | Folder with `DejaVuSans*.ttf` for full Unicode in PDFs (or put them in `./fonts`) |
| `FLASK_DEBUG=1` | Development only |

Email (SMTP) for welcome emails, password resets and emailed share links is configured in the app under **Admin → SMTP**.

---

## 🏭 Production

```bash
gunicorn -w 2 -b 127.0.0.1:5001 app:app
```

Run it behind an HTTPS reverse proxy and set `BEHIND_PROXY=1`. Back up `coresight.db`, `uploads/` and `.env`.

### 🐳 Docker

```bash
python3 init_env.py              # once, on the host: creates .env (back it up!)
docker compose up -d --build     # app on http://127.0.0.1:5001
```

- Database, uploads and backups live in the `vault-data` Docker volume (`/data` inside the container).
- A second `scheduler` container sends the expiry digest after 07:00 and makes a backup after 02:30 each day
  (set `TZ` and `BACKUP_PASSPHRASE` in `.env`). No host cron needed.
- Copy backups off the server: Admin → Backups → Download, or `docker compose cp vault:/data/backups ./backups-copy`.
- Upgrade: `git pull && docker compose up -d --build` (new columns are added automatically).

---

## 🔁 Scheduled jobs (cron)

```cron
0 7  * * *  cd /path/to/Core-docs && .venv/bin/python send_alerts.py     # expiry digest
30 2 * * *  cd /path/to/Core-docs && .venv/bin/python backup.py create   # nightly backup
```

Restore (stop the app first; current data is moved aside, not deleted): `python backup.py restore <file>`.
Back up `.env` separately: it holds the key that decrypts stored passwords and is deliberately not inside backups.

## 🧪 Tests

GitHub Actions runs these on every push and pull request (and checks the Docker image builds): see the *Actions* tab.

```bash
python tests/test_features.py     # 128 checks: CSRF, roles, record types, links, alerts, audit, backups, playbook,
                                  # read-only UI, expiry badge, welcome links, key rotation, folders/tags/rotation
```

---

## 🧑‍💻 Using the new features

- **Share a password:** open a password → *Share with a client* → choose how long the link lasts → Generate. Copy the link (shown once) or have it emailed.
- **Add a user:** Admin → Users → New User. Leave the password blank and they'll get an email link to choose their own
  (works once, expires in 72 hours). If email isn't set up yet, the link is shown to you once to pass on yourself.
- **Export a playbook:** open a client → *Export playbook (PDF)* → choose sections → Generate PDF. To include passwords, pick *Include passwords*, confirm your account password and set a PDF password (12+ characters).

---

## 🔐 Security Notes

- Keep `.env` private and backed up; never commit it
- Run behind HTTPS and restrict access (VPN/firewall)
- Every signed-in user can open every client; use the Read-only role for people who should only look
- Roles are global (Admin / Technician / Read-only); there is no per-client access control by design (MSP model)

---

## 📌 Roadmap

- API support
- RMM / Microsoft 365 / PSA / backup integrations
- Client portal
- Reporting

---

## 💡 About

Built for real-world MSP usage by CoreSight IT.
