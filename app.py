
import os
import secrets
import smtplib
import base64
import csv
import hashlib
import hmac
import json
import re
import io
from email.message import EmailMessage
from datetime import datetime, timedelta, date
from pathlib import Path
import io
import pyotp
import qrcode
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import playbook
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except Exception:
    pass
UPLOAD_ROOT = Path(os.environ.get("UPLOAD_DIR") or (BASE_DIR / "uploads"))   # override for tests / separate data disk
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-now")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'coresight.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))
app.config["RESET_TOKEN_SALT"] = "password-reset-salt"
app.config["VAULT_KEY"] = os.environ.get("VAULT_KEY")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # browsers won't send the login cookie on cross-site POSTs
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", os.environ.get("BEHIND_PROXY", "0")) == "1"
app.config["WTF_CSRF_TIME_LIMIT"] = None           # token lasts as long as the session

if os.environ.get("BEHIND_PROXY") == "1":
    # Set BEHIND_PROXY=1 when running behind nginx/Caddy/Traefik so that
    # share links use https:// and audit logs record the real client IP.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if app.config["SECRET_KEY"] == "change-this-now":
    print("WARNING: SECRET_KEY is not set. Run `python init_env.py` to generate a .env file.")
if not app.config["VAULT_KEY"]:
    print("WARNING: VAULT_KEY is not set; secrets are encrypted with a key derived from SECRET_KEY. "
          "Run `python init_env.py`, and never change these keys once data has been saved.")

# Print empty values as nothing rather than the word "None" (forms were saving "None" back as text).
app.jinja_env.finalize = lambda v: "" if v is None else v

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTS = {"pdf","doc","docx","xls","xlsx","ppt","pptx","txt","jpg","jpeg","png","gif","webp"}

# ---------------- Models ----------------

class OnboardingRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, unique=True, index=True)

    welcome_package_given = db.Column(db.Boolean, default=False)
    welcome_package_given_by = db.Column(db.String(200))
    welcome_package_given_on = db.Column(db.Date)

    site_contact_established = db.Column(db.Boolean, default=False)
    site_contact_established_by = db.Column(db.String(200))
    site_contact_established_on = db.Column(db.Date)

    rmm_installed = db.Column(db.Boolean, default=False)
    rmm_installed_by = db.Column(db.String(200))
    rmm_installed_on = db.Column(db.Date)

    m365_or_google_admin_created = db.Column(db.Boolean, default=False)
    m365_or_google_admin_created_by = db.Column(db.String(200))
    m365_or_google_admin_created_on = db.Column(db.Date)

    domain_taken_over = db.Column(db.Boolean, default=False)
    domain_taken_over_by = db.Column(db.String(200))
    domain_taken_over_on = db.Column(db.Date)

    network_scoped = db.Column(db.Boolean, default=False)
    network_scoped_by = db.Column(db.String(200))
    network_scoped_on = db.Column(db.Date)

    passwords_uploaded = db.Column(db.Boolean, default=False)
    passwords_uploaded_by = db.Column(db.String(200))
    passwords_uploaded_on = db.Column(db.Date)

    backups_set = db.Column(db.Boolean, default=False)
    backups_set_by = db.Column(db.String(200))
    backups_set_on = db.Column(db.Date)

    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
class DocPage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey("doc_folder.id"), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    body_html = db.Column(db.Text, nullable=False, default="")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    folder = db.relationship("DocFolder", backref="pages")
    created_by_user = db.relationship("User", foreign_keys=[created_by])
    updated_by_user = db.relationship("User", foreign_keys=[updated_by])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_totp_enabled = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(20), nullable=True)   # admin | tech | readonly



    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

class Password(db.Model):
    __tablename__ = "password"
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=True)
    username_plain = db.Column(db.String(500), nullable=True)
    password_plain = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    otp_secret = db.Column(db.String(64), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    updated_by_user = db.relationship("User", foreign_keys=[updated_by])
    folder = db.Column(db.String(100), nullable=True)            # e.g. "Network", "Microsoft 365"
    tags = db.Column(db.String(500), nullable=True)              # comma separated
    rotate_days = db.Column(db.Integer, nullable=True)           # remind to change every N days
    password_changed_at = db.Column(db.DateTime, nullable=True)  # when the secret itself last changed

    @property
    def tag_list(self):
        return parse_tags(self.tags)

    @property
    def rotation_due_on(self):
        """Date the password should next be changed, or None if no reminder is set."""
        if not self.rotate_days:
            return None
        base = self.password_changed_at or self.updated_at
        return (base.date() + timedelta(days=self.rotate_days)) if base else None

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, db.ForeignKey("password.id"), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    username_plain = db.Column(db.String(500), nullable=True)
    password_plain = db.Column(db.String(500), nullable=True)
    url = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    otp_secret = db.Column(db.String(64), nullable=True)
    changed_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    changed_by_user = db.relationship("User", foreign_keys=[changed_by])

class PasswordShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, db.ForeignKey("password.id"), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    recipient_email = db.Column(db.String(320), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    note = db.Column(db.String(500), nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    opened_ip = db.Column(db.String(64), nullable=True)
    created_by_user = db.relationship("User", foreign_keys=[created_by])

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    domain_name = db.Column(db.String(255), nullable=False, index=True)
    registrar = db.Column(db.String(255), nullable=True)
    dns_provider = db.Column(db.String(255), nullable=True)
    nameservers = db.Column(db.Text, nullable=True)
    expires_on = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)

class DocFolder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("doc_folder.id"), nullable=True)
    parent = db.relationship("DocFolder", remote_side=[id], backref="children")

class DocFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey("doc_folder.id"), nullable=True)
    file_name = db.Column(db.String(512), nullable=False)
    stored_name = db.Column(db.String(512), nullable=False)
    mime_type = db.Column(db.String(128), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    folder = db.relationship("DocFolder", backref="files")
    uploader = db.relationship("User", foreign_keys=[uploaded_by])

class SiteContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=True, index=True)
    mobile = db.Column(db.String(64), nullable=True)
    office = db.Column(db.String(64), nullable=True)
    position = db.Column(db.String(120), nullable=True)
    is_decision_maker = db.Column(db.Boolean, default=False, nullable=False)
    notes = db.Column(db.Text, nullable=True)

class SiteAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    site_name = db.Column(db.String(200), nullable=False)
    address1 = db.Column(db.String(200), nullable=False)
    address2 = db.Column(db.String(200), nullable=True)
    suburb = db.Column(db.String(120), nullable=True)
    state = db.Column(db.String(120), nullable=True)
    postcode = db.Column(db.String(20), nullable=True)
    country = db.Column(db.String(120), nullable=True, default="Australia")
    notes = db.Column(db.Text, nullable=True)

class NetworkDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    device_name = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    mac_address = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)

class AssetType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class AssetBrand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    device_name = db.Column(db.String(200), nullable=False)
    device_type = db.Column(db.String(120), nullable=True)
    brand = db.Column(db.String(120), nullable=True)
    date_purchased = db.Column(db.Date, nullable=True)
    serial_number = db.Column(db.String(200), nullable=True)
    asset_id = db.Column(db.String(200), nullable=True)
    location = db.Column(db.String(200), nullable=True)
    issued_to = db.Column(db.String(200), nullable=True)
    warranty_expires = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)


# ---------------- Custom record types, links, alerts ----------------
class CustomType(db.Model):
    """An admin-defined record type (e.g. Licence, Backup job, VPN) with its own fields."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    plural = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(300), nullable=True)
    fields_json = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @property
    def fields(self):
        try:
            return json.loads(self.fields_json or "[]")
        except Exception:
            return []

    @property
    def label_plural(self):
        return self.plural or (self.name + "s")


class CustomRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    type_id = db.Column(db.Integer, db.ForeignKey("custom_type.id"), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    data_json = db.Column(db.Text, nullable=False, default="{}")   # password-type fields are stored encrypted
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    ctype = db.relationship("CustomType")

    @property
    def data(self):
        try:
            return json.loads(self.data_json or "{}")
        except Exception:
            return {}


class RecordLink(db.Model):
    """Generic two-way link between any two records in the same organisation."""
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    a_type = db.Column(db.String(20), nullable=False)
    a_id = db.Column(db.Integer, nullable=False)
    b_type = db.Column(db.String(20), nullable=False)
    b_id = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("a_type", "a_id", "b_type", "b_id", name="uq_record_link"),)


class AlertSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    recipients = db.Column(db.Text, nullable=True)                 # comma / newline separated
    days = db.Column(db.String(100), nullable=False, default="60,30,14,7,1")
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_run_summary = db.Column(db.String(300), nullable=True)


class AlertSent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_key = db.Column(db.String(200), nullable=False, index=True)   # includes the expiry date, so a renewal re-arms it
    threshold = db.Column(db.Integer, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("item_key", "threshold", name="uq_alert_sent"),)


class SMTPSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=True)
    port = db.Column(db.Integer, default=587)
    username = db.Column(db.String(255), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    from_email = db.Column(db.String(255), nullable=True)
    use_tls = db.Column(db.Boolean, default=True)
    use_ssl = db.Column(db.Boolean, default=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False, index=True)
    entity_type = db.Column(db.String(120), nullable=False, index=True)
    entity_id = db.Column(db.String(120), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user = db.relationship("User", foreign_keys=[user_id])

class AssetAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), nullable=False, unique=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site_address.id"), nullable=True)
    contact_id = db.Column(db.Integer, db.ForeignKey("site_contact.id"), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="active")
    notes = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    asset = db.relationship("Asset", backref=db.backref("assignment", uselist=False))
    site = db.relationship("SiteAddress", foreign_keys=[site_id])
    contact = db.relationship("SiteContact", foreign_keys=[contact_id])
    updated_by_user = db.relationship("User", foreign_keys=[updated_by])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ---------------- Helpers ----------------
def build_totp_uri(user_email, secret):
    return pyotp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name="CoreSight Vault"
    )


def verify_totp_code(secret, code):
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)


def make_qr_data_uri(text):
    img = qrcode.make(text)
    buf = BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"

def generate_totp_code(secret):
    if not secret:
        return None

    try:
        import pyotp

        clean_secret = (
            decrypt_secret(secret)
            .replace(" ", "")
            .replace("-", "")
            .replace("\n", "")
            .strip()
            .upper()
        )

        if not clean_secret:
            return None

        return pyotp.TOTP(clean_secret).now()

    except Exception as e:
        print("TOTP ERROR:", e)
        return None

def _snippet(text, q, radius=80):
    if not text:
        return ""
    text = str(text)
    lower_text = text.lower()
    lower_q = q.lower()
    idx = lower_text.find(lower_q)
    if idx == -1:
        return text[: radius * 2].strip()
    start = max(0, idx - radius)
    end = min(len(text), idx + len(q) + radius)
    snippet = text[start:end].strip()
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet

MAX_TAGS = 20
ROTATION_CHOICES = [(0, "No reminder"), (30, "Every 30 days"), (60, "Every 60 days"), (90, "Every 90 days"),
                    (180, "Every 6 months"), (365, "Every year")]

def parse_tags(text):
    """'VPN, admin ,vpn' -> ['VPN', 'admin'] (trimmed, de-duplicated ignoring case, max 20 x 40 chars)."""
    out, seen = [], set()
    for t in (text or "").split(","):
        t = re.sub(r"\s+", " ", t).strip()[:40]
        if t and t.lower() not in seen:
            seen.add(t.lower()); out.append(t)
    return out[:MAX_TAGS]

def password_meta_from_form(form):
    """Folder / tags / rotation fields shared by the new + edit forms."""
    folder = re.sub(r"\s+", " ", (form.get("folder") or "")).strip()[:100] or None
    tags = ", ".join(parse_tags(form.get("tags"))) or None
    try:
        days = int(form.get("rotate_days") or 0)
    except ValueError:
        days = 0
    return folder, tags, (days if 0 < days <= 3650 else None)

def _get_vault_cipher():
    if Fernet is None:
        return None
    raw_key = app.config.get("VAULT_KEY")
    if raw_key:
        try:
            key = raw_key.encode() if isinstance(raw_key, str) else raw_key
            return Fernet(key)
        except Exception:
            pass
    derived = hashlib.sha256(app.config["SECRET_KEY"].encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(derived)
    return Fernet(key)

def encrypt_secret(value):
    if value is None or value == "":
        return None
    if isinstance(value, str) and value.startswith("enc:"):
        return value
    cipher = _get_vault_cipher()
    if cipher is None:
        return value
    token = cipher.encrypt(str(value).encode("utf-8")).decode("utf-8")
    return f"enc:{token}"

def decrypt_secret(value):
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        return str(value)
    if not value.startswith("enc:"):
        return value
    cipher = _get_vault_cipher()
    if cipher is None:
        return ""
    try:
        return cipher.decrypt(value[4:].encode("utf-8")).decode("utf-8")
    except Exception:
        return ""

def log_audit(action, entity_type, entity_id=None, org_id=None, details=None, user_id=None):
    try:
        entry = AuditLog(
            user_id=user_id if user_id is not None else (current_user.id if current_user.is_authenticated else None),
            org_id=org_id,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            details=details,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

def get_dashboard_data(org_id):
    now = datetime.utcnow().date()
    expiring_domains = Domain.query.filter(
        Domain.org_id == org_id,
        Domain.expires_on.isnot(None),
        Domain.expires_on <= (now + timedelta(days=60))
    ).order_by(Domain.expires_on.asc()).limit(10).all()

    recent_passwords = Password.query.filter_by(org_id=org_id).order_by(Password.updated_at.desc()).limit(10).all()
    assets_missing_serial = Asset.query.filter(
        Asset.org_id == org_id,
        db.or_(Asset.serial_number.is_(None), Asset.serial_number == "")
    ).count()

    docs_count = DocFile.query.filter_by(org_id=org_id).count() + DocPage.query.filter_by(org_id=org_id).count()
    password_count = Password.query.filter_by(org_id=org_id).count()
    contact_count = SiteContact.query.filter_by(org_id=org_id).count()
    asset_count = Asset.query.filter_by(org_id=org_id).count()
    onboarding = OnboardingRecord.query.filter_by(org_id=org_id).first()
    onboarding_done = 0
    onboarding_total = len(ONBOARDING_FIELDS)
    onboarding_percent = 0

    if onboarding:
        onboarding_done, onboarding_total, onboarding_percent = onboarding_progress(onboarding)

    return {
            "onboarding": {
            "done": onboarding_done,
            "total": onboarding_total,
            "percent": onboarding_percent,
        },
        "counts": {
            "passwords": password_count,
            "documents": docs_count,
            "contacts": contact_count,
            "assets": asset_count,
        },
        "expiring_domains": [
            {"id": d.id, "domain_name": d.domain_name, "expires_on": d.expires_on.strftime("%Y-%m-%d") if d.expires_on else ""}
            for d in expiring_domains
        ],
        "recent_passwords": [
            {"id": p.id, "name": p.name, "updated_at": p.updated_at.strftime("%Y-%m-%d %H:%M") if p.updated_at else ""}
            for p in recent_passwords
        ],
        "asset_issues": {"missing_serial_numbers": assets_missing_serial},
    }

def dns_query(name, record_type):
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=3)
        rows = []
        for rdata in answers:
            if record_type == "MX":
                rows.append({"type": "MX", "host": name, "value": str(rdata.exchange).rstrip("."), "priority": int(rdata.preference)})
            else:
                rows.append({"type": record_type, "host": name, "value": str(rdata).strip().rstrip(".")})
        return rows
    except Exception:
        return []

def fetch_dns_snapshot(domain_name):
    if not domain_name:
        return {"records": {"A": [], "MX": [], "TXT": [], "NS": [], "DMARC": []}, "email_health": [], "dns_available": False}

    a_records = dns_query(domain_name, "A")
    mx_records = dns_query(domain_name, "MX")
    txt_records = dns_query(domain_name, "TXT")
    ns_records = dns_query(domain_name, "NS")
    dmarc_records = dns_query(f"_dmarc.{domain_name}", "TXT")

    spf_record = None
    for record in txt_records:
        value = record["value"].strip('"')
        if value.lower().startswith("v=spf1"):
            spf_record = value
            break

    dmarc_record = None
    for record in dmarc_records:
        value = record["value"].strip('"')
        if value.lower().startswith("v=dmarc1"):
            dmarc_record = value
            break

    mx_values = [r["value"].lower() for r in mx_records]
    txt_values = [r["value"].strip('"').lower() for r in txt_records]
    email_health = []

    if mx_records:
        if any("mail.protection.outlook.com" in v for v in mx_values):
            email_health.append({"status": "success", "label": "MX", "message": "MX appears to point to Microsoft 365."})
        elif any("google.com" in v or "googlemail.com" in v or "aspmx.l.google.com" in v for v in mx_values):
            email_health.append({"status": "success", "label": "MX", "message": "MX appears to point to Google Workspace."})
        else:
            email_health.append({"status": "warning", "label": "MX", "message": "MX records exist, but provider was not recognised."})
    else:
        email_health.append({"status": "danger", "label": "MX", "message": "No MX records found."})

    email_health.append({"status": "success" if spf_record else "warning", "label": "SPF", "message": "SPF record found." if spf_record else "No SPF record found."})
    email_health.append({"status": "success" if dmarc_record else "warning", "label": "DMARC", "message": "DMARC record found." if dmarc_record else "No DMARC record found."})
    has_m365_dkim = any("onmicrosoft.com" in value for value in txt_values)
    email_health.append({"status": "success" if has_m365_dkim else "secondary", "label": "DKIM", "message": "Possible Microsoft 365 DKIM-related TXT records found." if has_m365_dkim else "DKIM was not validated by this basic lookup."})

    return {
        "records": {"A": a_records, "MX": mx_records, "TXT": txt_records, "NS": ns_records, "DMARC": dmarc_records},
        "email_health": email_health,
        "dns_available": dns is not None,
    }

def get_asset_assignment(asset_id):
    return AssetAssignment.query.filter_by(asset_id=asset_id).first()


def active_org():
    org_id = session.get("active_org_id")
    return db.session.get(Organization, org_id) if org_id else None

@app.context_processor
def inject_globals():
    ctx = {"active_org": active_org(), "role_name": None, "can_write": True, "custom_types": []}
    if current_user.is_authenticated:
        r = user_role(current_user)
        ctx["role_name"] = r
        ctx["can_write"] = r != "readonly"
        try:
            ctx["custom_types"] = CustomType.query.order_by(CustomType.name).all()
        except Exception:
            pass
    return ctx

def require_active_org():
    org = active_org()
    if not org:
        flash("Select an organisation first.", "warning")
        return None
    return org

def super_admin_only():
    if not current_user.is_authenticated or not current_user.is_super_admin:
        abort(403)

def password_meets_policy(pw):
    if not pw or len(pw) < 10:
        return False
    classes = 0
    if any(c.isupper() for c in pw): classes += 1
    if any(c.islower() for c in pw): classes += 1
    if any(c.isdigit() for c in pw): classes += 1
    if any(c in r'!@#$%^&*(),.?":{}|<>[]-_+=;/' for c in pw): classes += 1
    return classes >= 3

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS

def org_upload_dir(org_id):
    p = UPLOAD_ROOT / f"org_{org_id}"
    p.mkdir(parents=True, exist_ok=True)
    return p

def save_uploaded_file(file_storage, org_id):
    safe = secure_filename(file_storage.filename)
    stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{safe}"
    path = org_upload_dir(org_id) / stored
    file_storage.save(path)
    return safe, stored, path.stat().st_size

def get_smtp_settings():
    s = SMTPSettings.query.first()
    if not s:
        s = SMTPSettings()
        db.session.add(s)
        db.session.commit()
    return s

def send_email(to_email, subject, body):
    s = get_smtp_settings()
    if not s.host or not s.from_email:
        raise RuntimeError("SMTP settings are not configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s.from_email
    msg["To"] = to_email
    msg.set_content(body)
    if s.use_ssl:
        with smtplib.SMTP_SSL(s.host, s.port) as smtp:
            if s.username:
                smtp.login(s.username, s.password or "")
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(s.host, s.port) as smtp:
            if s.use_tls:
                smtp.starttls()
            if s.username:
                smtp.login(s.username, s.password or "")
            smtp.send_message(msg)

def serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])

RESET_LINK_MAX_AGE = 3600            # "forgot password" links: 1 hour
WELCOME_LINK_MAX_AGE = 72 * 3600     # new-user "set your password" links: 72 hours
WELCOME_TOKEN_SALT = "welcome-set-password"

def _pw_fingerprint(user):
    # Changes whenever the password changes, so every emailed link works only once.
    return hashlib.sha256((user.password_hash or "").encode()).hexdigest()[:16]

def generate_reset_token(user, welcome=False):
    salt = WELCOME_TOKEN_SALT if welcome else app.config["RESET_TOKEN_SALT"]
    return serializer().dumps({"e": user.email, "h": _pw_fingerprint(user)}, salt=salt)

def verify_reset_token(token):
    """Return (user, is_welcome) for a valid, unused link, else (None, False)."""
    for salt, max_age, welcome in ((app.config["RESET_TOKEN_SALT"], RESET_LINK_MAX_AGE, False),
                                   (WELCOME_TOKEN_SALT, WELCOME_LINK_MAX_AGE, True)):
        try:
            data = serializer().loads(token, salt=salt, max_age=max_age)
        except (BadSignature, SignatureExpired):
            continue
        if not isinstance(data, dict):
            return None, False
        user = User.query.filter_by(email=data.get("e")).first()
        if user and user.is_active_user and hmac.compare_digest(str(data.get("h")), _pw_fingerprint(user)):
            return user, welcome
        return None, False
    return None, False

def _to_date(value):
    if not value:
        return None
    if isinstance(value, (list, tuple, set)):
        vals = [_to_date(v) for v in value if v]
        vals = [v for v in vals if v]
        return max(vals) if vals else None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        s = value.strip()
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        try:
            return datetime.fromisoformat(s.replace("Z", "")).date()
        except Exception:
            return None
    return None

def infer_provider_from_nameservers(ns_list):
    if not ns_list: return None
    joined = " ".join((n or "").lower() for n in ns_list)
    if "cloudflare" in joined: return "Cloudflare"
    if "route53" in joined or "amazonaws" in joined: return "Amazon Route53"
    if "google" in joined: return "Google Domains / Cloud DNS"
    if "azure" in joined: return "Azure DNS"
    if "digitalocean" in joined: return "DigitalOcean"
    if "godaddy" in joined: return "GoDaddy"
    if "namecheap" in joined: return "Namecheap"
    return None

def fetch_whois_fields(domain_name):
    if not pywhois:
        raise RuntimeError("python-whois not installed")
    w = pywhois.whois(domain_name)
    reg = getattr(w, "registrar", None)
    registrar = (reg[0] if isinstance(reg, (list, tuple)) and reg else reg) or None
    exp_raw = getattr(w, "expiration_date", None) or getattr(w, "expiry_date", None)
    exp_date = _to_date(exp_raw)
    ns = getattr(w, "name_servers", None) or getattr(w, "nameservers", None)
    if isinstance(ns, (list, tuple, set)):
        ns_list = sorted({str(x).strip() for x in ns if x})
    elif isinstance(ns, str):
        ns_list = sorted({s.strip() for s in ns.split() if s.strip()})
    else:
        ns_list = []
    return {
        "registrar": registrar,
        "nameservers": ns_list,
        "dns_provider": infer_provider_from_nameservers(ns_list),
        "expires_on": exp_date,
        "expires_on_str": exp_date.strftime("%Y-%m-%d") if exp_date else "",
    }

@app.before_request
def enforce_password_change():
    allowed_endpoints = {
        "login",
        "login_mfa",
        "logout",
        "change_password",
        "forgot_password",
        "reset_password",
        "static",
    }

    if current_user.is_authenticated and current_user.must_change_password:
        if request.endpoint not in allowed_endpoints:
            return redirect(url_for("change_password"))

# ---------------- Roles ----------------
ROLES = [
    ("admin", "Admin", "Everything, including users, system settings, backups and password exports."),
    ("tech", "Technician", "Create, edit, delete and share client records. No user or system settings."),
    ("readonly", "Read-only", "View only. Cannot create, edit, delete, share or export."),
]
ROLE_KEYS = {r[0] for r in ROLES}
READONLY_POST_OK = {"login", "login_mfa", "logout", "change_password", "forgot_password",
                    "reset_password", "account", "setup_2fa", "static"}

def user_role(u):
    if u.is_super_admin or u.is_admin:
        return "admin"
    return u.role if u.role in ("tech", "readonly") else "tech"

def apply_role(u, role):
    role = role if role in ROLE_KEYS else "tech"
    u.role = role
    u.is_admin = u.is_super_admin = (role == "admin")

def other_active_admins(exclude_user_id):
    return User.query.filter(User.id != exclude_user_id, User.is_active_user.is_(True),
                             db.or_(User.is_super_admin.is_(True), User.is_admin.is_(True))).count()

@app.before_request
def enforce_roles():
    if not current_user.is_authenticated or user_role(current_user) != "readonly":
        return
    if request.method in ("GET", "HEAD", "OPTIONS") or request.endpoint in READONLY_POST_OK:
        return
    log_audit("denied", "role", None, details=f"Read-only user blocked: {request.method} {request.path}")
    if request.headers.get("X-Requested-With"):
        return jsonify({"success": False, "error": "Your account is read-only."}), 403
    flash("Your account is read-only, so that change wasn't made.", "warning")
    return redirect(request.referrer or url_for("orgs"))

# ---------------- CSRF ----------------
_FORM_POST_RE = re.compile(r'(<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>)', re.I)

@app.after_request
def inject_csrf_tokens(resp):
    """Add the CSRF token to every POST form in rendered pages, so templates don't each need it."""
    try:
        if (resp.mimetype != "text/html" or resp.direct_passthrough or resp.status_code >= 400
                or request.endpoint in ("pw_share_open", "static")):
            return resp
        html = resp.get_data(as_text=True)
        if "<form" not in html.lower() or 'name="csrf_token"' in html:
            return resp
        field = f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">'
        resp.set_data(_FORM_POST_RE.sub(lambda m: m.group(1) + field, html))
    except Exception:
        app.logger.exception("CSRF token injection failed")
    return resp

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.headers.get("X-Requested-With"):
        return jsonify({"success": False, "error": "Session expired. Reload the page and try again."}), 400
    flash("Your session expired or the form was invalid. Please try again.", "warning")
    return redirect(request.referrer or url_for("orgs"))

ONBOARDING_FIELDS = [
    ("welcome_package_given", "Welcome package given"),
    ("site_contact_established", "Site contact established"),
    ("rmm_installed", "RMM installed"),
    ("m365_or_google_admin_created", "M365/Google admin created"),
    ("domain_taken_over", "Domain taken over"),
    ("network_scoped", "Network scoped"),
    ("passwords_uploaded", "Passwords uploaded"),
    ("backups_set", "Backups set"),
]

def get_or_create_onboarding(org_id):
    row = OnboardingRecord.query.filter_by(org_id=org_id).first()
    if not row:
        row = OnboardingRecord(org_id=org_id)
        db.session.add(row)
        db.session.commit()
    return row

def onboarding_progress(row):
    total = len(ONBOARDING_FIELDS)
    done = sum(1 for field, _label in ONBOARDING_FIELDS if getattr(row, field, False))
    percent = int(round((done / total) * 100)) if total else 0
    return done, total, percent

@app.route("/onboarding", methods=["GET", "POST"])
@login_required
def onboarding_view():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    row = get_or_create_onboarding(org.id)

    if request.method == "POST":
        row.actioned_by = (request.form.get("actioned_by") or "").strip() or None

        actioned_on = (request.form.get("actioned_on") or "").strip()
        row.actioned_on = None
        if actioned_on:
            try:
                row.actioned_on = datetime.strptime(actioned_on, "%Y-%m-%d").date()
            except ValueError:
                flash("Actioned date must be YYYY-MM-DD.", "warning")
                return render_template(
                    "onboarding.html",
                    org=org,
                    row=row,
                    onboarding_fields=ONBOARDING_FIELDS,
                    progress=onboarding_progress(row)
                )

        for field, _label in ONBOARDING_FIELDS:
            is_checked = request.form.get(field) == "on"
            setattr(row, field, is_checked)

            # Per item metadata
            by_value = request.form.get(f"{field}_by")
            on_value = request.form.get(f"{field}_on")

            setattr(row, f"{field}_by", by_value or None)

            if on_value:
                try:
                    setattr(row, f"{field}_on", datetime.strptime(on_value, "%Y-%m-%d").date())
                except ValueError:
                    setattr(row, f"{field}_on", None)
            else:
                setattr(row, f"{field}_on", None)
        row.notes = (request.form.get("notes") or "").strip() or None
        row.updated_at = datetime.utcnow()

        db.session.commit()
        flash("Onboarding checklist saved.", "success")
        return redirect(url_for("onboarding_view"))

    return render_template(
        "onboarding.html",
        org=org,
        row=row,
        onboarding_fields=ONBOARDING_FIELDS,
        progress=onboarding_progress(row)
    )


@app.route("/onboarding/pdf")
@login_required
def onboarding_export_pdf():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    row = get_or_create_onboarding(org.id)
    done, total, percent = onboarding_progress(row)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Onboarding Checklist - {org.name}", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Progress:</b> {done} / {total} ({percent}%)", styles["Normal"]))
    story.append(Spacer(1, 12))

    data = [["Item", "Status", "Actioned By", "Actioned On"]]
    for field, label in ONBOARDING_FIELDS:
        is_complete = getattr(row, field, False)
        by_value = getattr(row, f"{field}_by", None) or "-"
        on_value = getattr(row, f"{field}_on", None)
        on_text = on_value.strftime("%d-%m-%Y") if on_value else "-"

        data.append([
            label,
            "Complete" if is_complete else "Pending",
            by_value,
            on_text
        ])

    table = Table(data, colWidths=[240, 80, 110, 90])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightyellow]),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("<b>Notes</b>", styles["Heading3"]))
    story.append(Paragraph((row.notes or "No notes added.").replace("\n", "<br/>"), styles["Normal"]))

    doc.build(story)
    buffer.seek(0)

    safe_name = "".join(c for c in org.name if c.isalnum() or c in (" ", "-", "_")).strip().replace(" ", "_")
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{safe_name}_onboarding_checklist.pdf",
        mimetype="application/pdf"
    )

# ---------------- Auth ----------------
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15

def is_locked(user):
    return bool(user.locked_until and datetime.utcnow() < user.locked_until)

@app.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("orgs"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid credentials.", "danger")
            return render_template("login.html")
        
        if not getattr(user, "is_active_user", True):
            flash("This account has been disabled.", "danger")
            return render_template("login.html")
        
        if is_locked(user) and not user.is_super_admin:
            flash("Account is temporarily locked.", "danger")
            return render_template("login.html")
        if not user.check_password(pw):
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= LOCKOUT_THRESHOLD and not user.is_super_admin:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            db.session.commit()
            flash("Invalid credentials.", "danger")
            return render_template("login.html")
        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        if user.is_totp_enabled and user.totp_secret:
            session["preauth_user_id"] = user.id
            flash("Enter your MFA code to continue.", "info")
            return redirect(url_for("login_mfa"))
        login_user(user)
        log_audit("login", "user", user.id, details="Successful login", user_id=user.id)

        if user.must_change_password:
            flash("You must change your password before continuing.", "warning")
            return redirect(url_for("change_password"))

        return redirect(url_for("orgs"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_audit("logout", "user", current_user.id, details="User logged out")
    logout_user()
    session.pop("active_org_id", None)
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = generate_reset_token(user)
                reset_url = url_for("reset_password", token=token, _external=True)
                send_email(user.email, "Password Reset Request", f"Use this link to reset your password:\n\n{reset_url}")
            except Exception as e:
                flash(f"SMTP not configured or email failed: {e}", "danger")
                return render_template("forgot_password.html")
        flash("If that email exists, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user, welcome = verify_reset_token(token)
    if not user:
        flash("This link is invalid, has expired, or has already been used. Request a new one below, "
              "or ask your administrator.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        if pw != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("reset_password.html", welcome=welcome, email=user.email)
        if not password_meets_policy(pw):
            flash("Password must be at least 10 characters and use 3 of: upper case, lower case, numbers, symbols.", "warning")
            return render_template("reset_password.html", welcome=welcome, email=user.email)
        user.set_password(pw)
        user.must_change_password = False
        user.failed_logins = 0
        user.locked_until = None
        db.session.commit()
        log_audit("set_password" if welcome else "reset_password", "user", user.id,
                  details=("Set initial password via welcome link" if welcome else "Reset password via email link"), user_id=user.id)
        flash("Password set. You can now sign in." if welcome else "Password reset complete.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", welcome=welcome, email=user.email)

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    force = bool(current_user.must_change_password)
    if request.method == "POST":
        current_pw = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not current_user.check_password(current_pw):
            flash("Your current password is incorrect.", "danger")
        elif new_password != confirm_password:
            flash("New passwords do not match.", "danger")
        elif new_password == current_pw:
            flash("Choose a password different from your current one.", "danger")
        elif not password_meets_policy(new_password):
            flash("Password must be at least 10 characters and include at least 3 of: "
                  "uppercase, lowercase, number, symbol.", "danger")
        else:
            current_user.set_password(new_password)
            current_user.must_change_password = False
            db.session.commit()
            log_audit("change_password", "user", current_user.id, details="Password changed")
            flash("Password changed successfully.", "success")
            return redirect(url_for("orgs"))
    return render_template("change_password.html", force_change=force)


@app.route("/setup-2fa")
@login_required
def setup_2fa():
    return render_template("setup_2fa.html")

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def admin_user_edit(user_id):
    super_admin_only()

    edit_user = db.session.get(User, user_id)
    if not edit_user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        edit_user.email = (request.form.get("email") or "").strip().lower()
        new_role = request.form.get("role") or user_role(edit_user)
        new_active = True if request.form.get("is_active_user") else False
        if (user_role(edit_user) == "admin" and edit_user.is_active_user
                and (new_role != "admin" or not new_active)
                and other_active_admins(edit_user.id) == 0):
            flash("You can't demote or disable the only active admin.", "danger")
            return render_template("admin_user_edit.html", edit_user=edit_user, roles=ROLES, cur_role=user_role(edit_user))
        apply_role(edit_user, new_role)
        edit_user.is_active_user = new_active
        edit_user.must_change_password = True if request.form.get("must_change_password") else False

        new_password = request.form.get("new_password") or ""

        if new_password:
            if not password_meets_policy(new_password):
                flash("Password does not meet policy.", "warning")
                return render_template("admin_user_edit.html", edit_user=edit_user, roles=ROLES, cur_role=user_role(edit_user))

            edit_user.set_password(new_password)
            edit_user.must_change_password = True

        db.session.commit()

        log_audit(
            "update",
            "user",
            edit_user.id,
            details=f"Updated user: {edit_user.email}",
            user_id=current_user.id
        )

        flash("User updated.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_user_edit.html", edit_user=edit_user, roles=ROLES, cur_role=user_role(edit_user))

@app.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    user_id = session.get("preauth_user_id")

    if not user_id:
        flash("Login expired. Please sign in again.", "warning")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if not user:
        session.pop("preauth_user_id", None)
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code") or ""

        if not verify_totp_code(user.totp_secret, code):
            flash("Invalid MFA code.", "danger")
            return render_template("login_mfa.html", email=user.email)

        session.pop("preauth_user_id", None)

        login_user(user)
        flash("Login successful.", "success")
        return redirect(url_for("orgs"))

    return render_template("login_mfa.html", email=user.email)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "change_password":
            current_pw = request.form.get("current_password") or ""
            new_pw = request.form.get("new_password") or ""
            confirm_pw = request.form.get("confirm_password") or ""

            if not current_user.check_password(current_pw):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("account"))

            if new_pw != confirm_pw:
                flash("New passwords do not match.", "warning")
                return redirect(url_for("account"))

            if not password_meets_policy(new_pw):
                flash("Password does not meet policy.", "warning")
                return redirect(url_for("account"))

            current_user.set_password(new_pw)
            current_user.must_change_password = False
            db.session.commit()

            log_audit(
                "change_password",
                "user",
                current_user.id,
                details="User changed own password",
                user_id=current_user.id
            )

            flash("Password changed.", "success")
            return redirect(url_for("account"))

    return render_template("account.html")
#-----------------Onboarding------------


# ---------------- Orgs ----------------
@app.route("/home/reset")
@login_required
def home_reset():
    session.pop("active_org_id", None)
    flash("Organisation selection cleared.", "info")
    return redirect(url_for("orgs"))

@app.route("/orgs")
@login_required
def orgs():
    rows = Organization.query.order_by(Organization.name.asc()).all()
    return render_template("orgs.html", orgs=rows)

@app.route("/orgs/new", methods=["GET", "POST"])
@login_required
def org_new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        desc = (request.form.get("description") or "").strip() or None
        if not name:
            flash("Name is required.", "warning")
            return render_template("org_new.html")
        if Organization.query.filter_by(name=name).first():
            flash("Organisation already exists.", "warning")
            return render_template("org_new.html")
        o = Organization(name=name, description=desc)
        db.session.add(o)
        db.session.commit()
        flash("Organisation created.", "success")
        return redirect(url_for("orgs"))
    return render_template("org_new.html")

@app.route("/org/<int:org_id>")
@login_required
def org_view(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        abort(404)
    session["active_org_id"] = org.id

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/") and not next_url.startswith("//") and "\\" not in next_url:
        return redirect(next_url)

    dashboard_data = get_dashboard_data(org.id)
    return render_template("org_view.html", org=org, dashboard_data=dashboard_data)


@app.route("/orgs/<int:org_id>/edit", methods=["GET", "POST"])
@login_required
def org_edit(org_id):
    super_admin_only()
    org = db.session.get(Organization, org_id)
    if not org:
        abort(404)

    if request.method == "POST":
        org.name = (request.form.get("name") or "").strip()
        org.description = (request.form.get("description") or "").strip() or None

        if not org.name:
            flash("Name is required.", "warning")
            return render_template("org_edit.html", org=org)

        db.session.commit()
        flash("Organisation saved.", "success")
        return redirect(url_for("org_view", org_id=org.id))

    return render_template("org_edit.html", org=org)

# ---------------- Passwords ----------------
@app.route("/passwords")
@login_required
def pw_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    all_rows = Password.query.filter_by(org_id=org.id).order_by(Password.name.asc()).all()
    folder = request.args.get("folder")          # None = all, "" = no folder
    tag = (request.args.get("tag") or "").strip()
    q = (request.args.get("q") or "").strip().lower()
    rows = all_rows
    if folder is not None:
        rows = [r for r in rows if (r.folder or "") == folder]
    if tag:
        rows = [r for r in rows if tag.lower() in (t.lower() for t in r.tag_list)]
    if q:
        rows = [r for r in rows if q in (r.name or "").lower() or q in (r.url or "").lower()
                or q in (r.folder or "").lower() or any(q in t.lower() for t in r.tag_list)]
    groups = {}
    for r in rows:
        groups.setdefault(r.folder or "", []).append(r)
    grouped = sorted(groups.items(), key=lambda kv: (kv[0] == "", kv[0].lower()))   # "no folder" last
    folders = sorted({r.folder for r in all_rows if r.folder}, key=str.lower)
    tag_counts = {}
    for r in all_rows:
        for t in r.tag_list:
            k = t.lower()
            tag_counts[k] = (tag_counts.get(k, (t, 0))[0], tag_counts.get(k, (t, 0))[1] + 1)
    all_tags = sorted(tag_counts.values(), key=lambda tc: tc[0].lower())
    today = date.today()
    return render_template("pw_list.html", org=org, passwords=rows, grouped=grouped, folders=folders,
                           all_tags=all_tags, cur_folder=folder, cur_tag=tag, q=request.args.get("q") or "",
                           today=today, total=len(all_rows))

@app.route("/passwords/new", methods=["GET", "POST"])
@login_required
def pw_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        p = Password(
            org_id=org.id,
            name=(request.form.get("name") or "").strip(),
            username_plain=encrypt_secret(request.form.get("username") or None),
            password_plain=encrypt_secret(request.form.get("password") or None),
            url=request.form.get("url") or None,
            notes=request.form.get("notes") or None,
            otp_secret=encrypt_secret((request.form.get("otp_secret") or "").replace(" ", "").strip().upper() or None),
            updated_at=datetime.utcnow(),
            updated_by=current_user.id
        )
        p.folder, p.tags, p.rotate_days = password_meta_from_form(request.form)
        p.password_changed_at = datetime.utcnow() if request.form.get("password") else None
        if not p.name:
            flash("Name required.", "warning")
            return render_template("pw_edit.html", org=org, row=None, **pw_form_context(org))
        db.session.add(p)
        db.session.commit()
        log_audit("create", "password", p.id, org_id=org.id, details=f"Created password: {p.name}")
        flash("Password created.", "success")
        return redirect(url_for("pw_view", pw_id=p.id))
    return render_template("pw_edit.html", org=org, row=None, **pw_form_context(org))

@app.route("/passwords/import", methods=["GET", "POST"])
@login_required
def pw_import():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "GET":
        return render_template("pw_import.html", org=org)

    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV file to import.", "warning")
        return render_template("pw_import.html", org=org)
    if not upload.filename.lower().endswith(".csv"):
        flash("The import file must have a .csv extension.", "warning")
        return render_template("pw_import.html", org=org)

    try:
        text = upload.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("The CSV file must use UTF-8 encoding.", "warning")
        return render_template("pw_import.html", org=org)

    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("The CSV file does not contain a header row.")
        headers = {(header or "").strip().lower(): header for header in reader.fieldnames}
        if "name" not in headers:
            raise ValueError("The CSV header must include a name column.")

        imported = []
        errors = []
        for line_number, source_row in enumerate(reader, start=2):
            if line_number > 10001:
                raise ValueError("A maximum of 10,000 password records can be imported at once.")
            if None in source_row:
                errors.append(f"Row {line_number}: contains more values than the header row.")
                continue
            row = {
                (key or "").strip().lower(): (value or "").strip()
                for key, value in source_row.items()
                if key is not None
            }
            if not any(row.values()):
                continue
            name = row.get("name", "")
            if not name:
                errors.append(f"Row {line_number}: name is required.")
                continue
            if len(name) > 200:
                errors.append(f"Row {line_number}: name cannot exceed 200 characters.")
                continue
            imported.append(Password(
                org_id=org.id,
                name=name,
                username_plain=encrypt_secret(row.get("username") or None),
                password_plain=encrypt_secret(row.get("password") or None),
                url=(row.get("url") or None),
                notes=(row.get("notes") or None),
                otp_secret=encrypt_secret(row.get("otp_secret") or None),
                updated_at=datetime.utcnow(),
                updated_by=current_user.id,
                folder=(re.sub(r"\s+", " ", row.get("folder") or "").strip()[:100] or None),
                tags=(", ".join(parse_tags(row.get("tags"))) or None),
                password_changed_at=(datetime.utcnow() if row.get("password") else None),
            ))
    except (csv.Error, ValueError) as exc:
        flash(f"Unable to import CSV: {exc}", "danger")
        return render_template("pw_import.html", org=org)

    if errors:
        flash("No passwords were imported. " + " ".join(errors[:10]), "danger")
        if len(errors) > 10:
            flash(f"Plus {len(errors) - 10} additional row errors.", "danger")
        return render_template("pw_import.html", org=org)
    if not imported:
        flash("The CSV file did not contain any password records.", "warning")
        return render_template("pw_import.html", org=org)

    db.session.add_all(imported)
    db.session.commit()
    log_audit(
        "import",
        "password",
        org_id=org.id,
        details=f"Imported {len(imported)} password records from CSV",
    )
    flash(f"Imported {len(imported)} password records.", "success")
    return redirect(url_for("pw_list"))
@app.route("/passwords/<int:pw_id>/otp")
@login_required
def pw_otp(pw_id):
    org = require_active_org()
    row = db.session.get(Password, pw_id)

    if not org or not row or row.org_id != org.id:
        return jsonify({"error": "not found"}), 404

    code = generate_totp_code(row.otp_secret)

    if not code:
        return jsonify({"otp": "", "message": "No valid OTP configured"})

    return jsonify({"otp": code})


@app.route("/passwords/<int:pw_id>", methods=["GET", "POST"])
@login_required
def pw_edit(pw_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    row = db.session.get(Password, pw_id)
    if not row or row.org_id != org.id:
        flash("Password not found.", "danger")
        return redirect(url_for("pw_list"))

    if request.method == "POST":
        hist = PasswordHistory(
            password_id=row.id,
            org_id=row.org_id,
            name=row.name,
            username_plain=row.username_plain,
            password_plain=row.password_plain,
            url=row.url,
            notes=row.notes,
            otp_secret=row.otp_secret,
            changed_by=current_user.id
        )
        db.session.add(hist)

        otp_secret = (
            (request.form.get("otp_secret") or "")
            .replace(" ", "")
            .replace("-", "")
            .replace("\n", "")
            .strip()
            .upper()
        )

        new_pw = request.form.get("password") or ""
        if new_pw != decrypt_secret(row.password_plain):
            row.password_changed_at = datetime.utcnow()      # restarts the rotation reminder
        row.name = (request.form.get("name") or "").strip()
        row.username_plain = encrypt_secret(request.form.get("username") or None)
        row.password_plain = encrypt_secret(new_pw or None)
        # The form never shows the existing 2FA secret, so a blank box means "keep it".
        if request.form.get("clear_otp") == "1":
            row.otp_secret = None
        elif otp_secret:
            row.otp_secret = encrypt_secret(otp_secret)
        row.url = request.form.get("url") or None
        row.notes = request.form.get("notes") or None
        row.folder, row.tags, row.rotate_days = password_meta_from_form(request.form)
        row.updated_at = datetime.utcnow()
        row.updated_by = current_user.id

        if not row.name:
            db.session.rollback()
            flash("Name required.", "warning")
            return redirect(url_for("pw_edit", pw_id=pw_id))

        db.session.commit()
        log_audit("update", "password", row.id, org_id=org.id, details=f"Updated password: {row.name}")
        flash("Password updated.", "success")
        return redirect(url_for("pw_view", pw_id=row.id))

    edit_row = {
        "id": row.id,
        "name": row.name,
        "url": row.url,
        "username_plain": decrypt_secret(row.username_plain),
        "password_plain": decrypt_secret(row.password_plain),
        "has_otp": bool(row.otp_secret),
        "notes": row.notes,
        "folder": row.folder,
        "tags": row.tags,
        "rotate_days": row.rotate_days or 0,
        "rotation_due_on": row.rotation_due_on,
        "password_changed_at": row.password_changed_at,
    }

    return render_template("pw_edit.html", org=org, row=edit_row, **pw_form_context(org))

def pw_form_context(org):
    """Suggestions for the folder/tag boxes: what this client already uses."""
    rows = Password.query.filter_by(org_id=org.id).with_entities(Password.folder, Password.tags).all()
    folders = sorted({f for f, _ in rows if f}, key=str.lower)
    tags = sorted({t for _, ts in rows for t in parse_tags(ts)}, key=str.lower)
    return {"folder_options": folders, "tag_options": tags, "rotation_choices": ROTATION_CHOICES}

@app.route("/passwords/<int:pw_id>/view")
@login_required
def pw_view(pw_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    row = db.session.get(Password, pw_id)
    if not row or row.org_id != org.id:
        flash("Password not found.", "danger")
        return redirect(url_for("pw_list"))
    history = PasswordHistory.query.filter_by(password_id=row.id).order_by(PasswordHistory.changed_at.desc()).all()
    now = datetime.utcnow()
    shares = [
        {"s": s, "status": share_status(s, now)}
        for s in PasswordShareLink.query.filter_by(password_id=row.id)
        .order_by(PasswordShareLink.created_at.desc()).limit(15).all()
    ]
    new_share = session.pop("new_share_link", None)
    if new_share and new_share.get("pw_id") != row.id:
        new_share = None
    return render_template(
        "pw_view.html", org=org, row=row, history=history, today=date.today(),
        shares=shares, new_share=new_share, share_choices=SHARE_EXPIRY_CHOICES,
        share_default=SHARE_DEFAULT_MINUTES,
    )

@app.route("/passwords/<int:pw_id>/delete", methods=["POST"])
@login_required
def pw_delete(pw_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    row = db.session.get(Password, pw_id)
    if not row or row.org_id != org.id:
        flash("Password not found.", "danger")
        return redirect(url_for("pw_list"))
    PasswordShareLink.query.filter_by(password_id=row.id).delete()
    db.session.delete(row)
    db.session.commit()
    log_audit("delete", "password", pw_id, org_id=org.id, details=f"Deleted password: {row.name}")
    flash("Password deleted.", "success")
    return redirect(url_for("pw_list"))

@app.route("/passwords/<int:pw_id>/rollback/<int:history_id>", methods=["POST"])
@login_required
def pw_rollback(pw_id, history_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    row = db.session.get(Password, pw_id)
    hist = db.session.get(PasswordHistory, history_id)
    if not row or row.org_id != org.id or not hist or hist.password_id != row.id:
        flash("History entry not found.", "danger")
        return redirect(url_for("pw_view", pw_id=pw_id))
    snapshot = PasswordHistory(
        password_id=row.id,
        org_id=row.org_id,
        name=row.name,
        username_plain=row.username_plain,
        password_plain=row.password_plain,
        url=row.url,
        notes=row.notes,
        otp_secret=row.otp_secret,
        changed_by=current_user.id
    )
    db.session.add(snapshot)
    row.name = hist.name
    row.username_plain = hist.username_plain
    row.password_plain = hist.password_plain
    row.url = hist.url
    row.notes = hist.notes
    row.otp_secret = hist.otp_secret
    row.updated_at = datetime.utcnow()
    row.updated_by = current_user.id
    db.session.commit()
    flash("Password rolled back successfully.", "success")
    return redirect(url_for("pw_view", pw_id=row.id))

@app.route("/passwords/<int:pw_id>/secret")
@login_required
def pw_secret(pw_id):
    org = require_active_org()
    row = db.session.get(Password, pw_id)

    if not org or not row or row.org_id != org.id:
        return jsonify({"error": "not found"}), 404

    log_audit("reveal", "password", row.id, org_id=org.id, details=f"Revealed password record: {row.name}")
    resp = jsonify({
        "username": decrypt_secret(row.username_plain) or "",
        "password": decrypt_secret(row.password_plain) or "",
        "otp_secret": decrypt_secret(row.otp_secret) or ""
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------- One-time password sharing ----------------
# Flow: staff create a link (default 5 min) -> recipient opens it and sees a
# confirmation page (GET never consumes the link, so email scanners/previews
# can't burn it) -> recipient clicks "Reveal" (POST) -> link is atomically
# consumed and the secret is shown once, with an on-screen countdown.
SHARE_EXPIRY_CHOICES = [(5, "5 minutes"), (15, "15 minutes"), (60, "1 hour"), (1440, "24 hours")]
SHARE_DEFAULT_MINUTES = 5
SHARE_MAX_MINUTES = 1440
SHARE_VIEW_SECONDS = 300  # how long the revealed secret stays on screen

def _share_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def share_status(share, now=None):
    now = now or datetime.utcnow()
    if share.revoked_at is not None:
        return "revoked"
    if share.used_at is not None:
        return "used"
    if now > share.expires_at:
        return "expired"
    return "active"

def _share_response(html):
    resp = app.make_response(html)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.route("/passwords/<int:pw_id>/share", methods=["POST"])
@login_required
def pw_share(pw_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    row = db.session.get(Password, pw_id)
    if not row or row.org_id != org.id:
        flash("Password not found.", "danger")
        return redirect(url_for("pw_list"))

    recipient_email = (request.form.get("recipient_email") or "").strip() or None
    note = (request.form.get("note") or "").strip()[:500] or None
    try:
        expires_minutes = int((request.form.get("expires_minutes") or str(SHARE_DEFAULT_MINUTES)).strip())
    except ValueError:
        expires_minutes = SHARE_DEFAULT_MINUTES
    expires_minutes = max(1, min(expires_minutes, SHARE_MAX_MINUTES))

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)
    share = PasswordShareLink(
        password_id=row.id,
        org_id=org.id,
        token_hash=_share_hash(token),
        recipient_email=recipient_email,
        note=note,
        expires_at=expires_at,
        created_by=current_user.id,
    )
    db.session.add(share)
    db.session.commit()
    log_audit(
        "share_create", "password", row.id, org_id=org.id,
        details=f"Created one-time link for '{row.name}' (expires in {expires_minutes} min"
                + (f", sent to {recipient_email}" if recipient_email else "") + ")",
    )

    share_url = url_for("pw_share_open", token=token, _external=True)
    emailed = False
    if recipient_email:
        try:
            send_email(
                recipient_email,
                f"Secure one-time password link: {row.name}",
                "A password has been securely shared with you.\n\n"
                f"Open this link: {share_url}\n\n"
                f"The link expires in {expires_minutes} minute(s) (at {expires_at.strftime('%Y-%m-%d %H:%M UTC')}) "
                "and can only be revealed once. Copy the details somewhere safe as soon as you open it.",
            )
            emailed = True
            flash("One-time link emailed.", "success")
        except Exception as e:
            flash(f"Link generated, but email failed: {e}", "warning")
    else:
        flash("One-time link generated.", "success")

    # Hand the link to pw_view once via the session rather than the query string
    # (query strings end up in browser history and server logs).
    session["new_share_link"] = {
        "pw_id": row.id,
        "url": share_url,
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M UTC"),
        "minutes": expires_minutes,
        "emailed": emailed,
    }
    return redirect(url_for("pw_view", pw_id=row.id))

@app.route("/passwords/<int:pw_id>/share/<int:share_id>/revoke", methods=["POST"])
@login_required
def pw_share_revoke(pw_id, share_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    share = db.session.get(PasswordShareLink, share_id)
    if not share or share.password_id != pw_id or share.org_id != org.id:
        flash("Share link not found.", "danger")
        return redirect(url_for("pw_view", pw_id=pw_id))
    if share_status(share) == "active":
        share.revoked_at = datetime.utcnow()
        db.session.commit()
        log_audit("share_revoke", "password", pw_id, org_id=org.id, details="Revoked one-time link")
        flash("Share link revoked.", "success")
    return redirect(url_for("pw_view", pw_id=pw_id))

@app.route("/shared/password/<token>", methods=["GET", "POST"])
def pw_share_open(token):
    share = PasswordShareLink.query.filter_by(token_hash=_share_hash(token)).first()
    now = datetime.utcnow()

    def unavailable():
        # One generic message for expired / used / revoked / unknown, so the
        # page doesn't reveal anything about the link.
        return _share_response(render_template("shared_password_view.html", state="unavailable"))

    if not share or share_status(share, now) != "active":
        return unavailable()
    row = db.session.get(Password, share.password_id)
    if not row or row.org_id != share.org_id:
        return unavailable()

    if request.method == "GET":
        return _share_response(render_template(
            "shared_password_view.html", state="ready", row=row, share=share,
            seconds_left=max(0, int((share.expires_at - now).total_seconds())),
        ))

    # POST: consume atomically so two simultaneous requests can't both succeed.
    ip = (request.remote_addr or "")[:64]
    claimed = PasswordShareLink.query.filter(
        PasswordShareLink.id == share.id,
        PasswordShareLink.used_at.is_(None),
        PasswordShareLink.revoked_at.is_(None),
        PasswordShareLink.expires_at > now,
    ).update({"used_at": now, "opened_ip": ip}, synchronize_session=False)
    db.session.commit()
    if claimed != 1:
        return unavailable()

    log_audit(
        "share_reveal", "password", row.id, org_id=row.org_id,
        details=f"One-time link used for '{row.name}' from {ip or 'unknown IP'}",
        user_id=share.created_by,
    )
    return _share_response(render_template(
        "shared_password_view.html", state="revealed", row=row, share=share,
        username=decrypt_secret(row.username_plain),
        password=decrypt_secret(row.password_plain),
        view_seconds=SHARE_VIEW_SECONDS,
    ))


# ---------------- Client playbook (PDF export) ----------------
def collect_playbook_data(org, include_passwords):
    """Gather everything for one organisation into plain dicts for playbook.py."""
    def folder_path(folder_id):
        parts, seen = [], set()
        f = db.session.get(DocFolder, folder_id) if folder_id else None
        while f and f.id not in seen:
            seen.add(f.id)
            parts.append(f.name)
            f = f.parent
        return " / ".join(reversed(parts))

    contacts = SiteContact.query.filter_by(org_id=org.id).order_by(SiteContact.last_name, SiteContact.first_name).all()
    sites = SiteAddress.query.filter_by(org_id=org.id).order_by(SiteAddress.site_name).all()
    net = NetworkDevice.query.filter_by(org_id=org.id).order_by(NetworkDevice.device_name).all()
    domains = Domain.query.filter_by(org_id=org.id).order_by(Domain.domain_name).all()
    assets_ = Asset.query.filter_by(org_id=org.id).order_by(Asset.device_name).all()
    pages = DocPage.query.filter_by(org_id=org.id).all()
    files = DocFile.query.filter_by(org_id=org.id).all()
    pws = Password.query.filter_by(org_id=org.id).order_by(Password.name).all()
    custom_recs = CustomRecord.query.filter_by(org_id=org.id).order_by(CustomRecord.name).all()
    ob = get_or_create_onboarding(org.id)

    def related(kind, eid):
        return [f"{d['kind_label']}: {d['name']}" for d in links_for(kind, eid, org.id)]

    record_groups = {}
    for r in custom_recs:
        fields = []
        for f in r.ctype.fields:
            v = r.data.get(f["key"], "")
            if f["type"] == "password":
                v = decrypt_secret(v) if (include_passwords and v) else ("(omitted)" if v else "")
            elif f["type"] == "checkbox":
                v = "Yes" if v else "No"
            fields.append({"label": f["label"], "value": v, "type": f["type"]})
        g = record_groups.setdefault(r.type_id, {"name": r.ctype.label_plural, "singular": r.ctype.name, "records": []})
        g["records"].append({"name": r.name, "fields": fields, "related": related("record", r.id), "updated": r.updated_at})
    done, total, percent = onboarding_progress(ob)

    def site_addr(s):
        line3 = " ".join(x for x in [s.suburb, s.state, s.postcode] if x)
        return "\n".join(x for x in [s.address1, s.address2, line3, s.country] if x)

    upload_dir = org_upload_dir(org.id).resolve()
    file_rows = []
    for f in sorted(files, key=lambda x: (folder_path(x.folder_id).lower(), x.file_name.lower())):
        disk = (upload_dir / Path(f.stored_name).name).resolve()
        ok = disk.is_file() and str(disk).startswith(str(upload_dir))
        file_rows.append({
            "name": f.file_name, "path": folder_path(f.folder_id), "size": f.size_bytes,
            "uploaded": f.uploaded_at, "disk_path": str(disk) if ok else None,
        })

    page_rows = sorted(
        ({"title": p.title, "path": folder_path(p.folder_id), "html": p.body_html, "updated": p.updated_at} for p in pages),
        key=lambda x: (x["path"].lower(), x["title"].lower()),
    )

    return {
        "org": {"name": org.name, "description": org.description},
        "generated_at": datetime.utcnow(),
        "generated_by": current_user.email,
        "counts": {
            "Contacts": len(contacts), "Sites": len(sites), "Network devices": len(net), "Domains": len(domains),
            "Assets": len(assets_), "Documents": len(pages), "Files": len(files), "Passwords": len(pws),
            "Custom records": len(custom_recs),
        },
        "onboarding": {
            "done": done, "total": total, "percent": percent, "notes": ob.notes,
            "items": [(label, bool(getattr(ob, f)), getattr(ob, f + "_by", None), getattr(ob, f + "_on", None))
                      for f, label in ONBOARDING_FIELDS],
        },
        "contacts": [{"first": c.first_name, "last": c.last_name, "position": c.position, "email": c.email,
                      "mobile": c.mobile, "office": c.office, "decision": c.is_decision_maker, "notes": c.notes}
                     for c in contacts],
        "sites": [{"name": s.site_name, "address": site_addr(s), "notes": s.notes, "related": related("site", s.id)} for s in sites],
        "network": [{"name": n.device_name, "ip": n.ip_address, "mac": n.mac_address, "notes": n.notes} for n in net],
        "domains": [{"name": d.domain_name, "registrar": d.registrar, "dns_provider": d.dns_provider,
                     "nameservers": d.nameservers, "expires": d.expires_on, "notes": d.notes,
                     "related": related("domain", d.id)} for d in domains],
        "assets": [{
            "name": a.device_name, "type": a.device_type, "brand": a.brand, "serial": a.serial_number,
            "asset_id": a.asset_id, "purchased": a.date_purchased, "warranty": a.warranty_expires, "issued_to": a.issued_to, "location": a.location,
            "notes": a.notes, "related": related("asset", a.id),
            "status": a.assignment.status if a.assignment else None,
            "site": a.assignment.site.site_name if a.assignment and a.assignment.site else None,
            "contact": (f"{a.assignment.contact.first_name} {a.assignment.contact.last_name}"
                        if a.assignment and a.assignment.contact else None),
        } for a in assets_],
        "doc_pages": page_rows,
        "files": file_rows,
        "passwords": [{
            "name": p.name, "url": p.url, "username": decrypt_secret(p.username_plain),
            # only decrypt secrets when they will actually be written to the PDF
            "password": decrypt_secret(p.password_plain) if include_passwords else None,
            "otp_secret": decrypt_secret(p.otp_secret) if include_passwords else None,
            "notes": p.notes, "updated": p.updated_at, "related": related("password", p.id),
        } for p in pws],
        "records": list(record_groups.values()),
    }

PLAYBOOK_SECTIONS = [k for k, _ in playbook.SECTION_ORDER]

@app.route("/orgs/<int:org_id>/export", methods=["GET", "POST"])
@login_required
def org_export(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        abort(404)
    session["active_org_id"] = org.id
    can_export_pw = bool(current_user.is_admin or current_user.is_super_admin)

    if request.method == "GET":
        return render_template("org_export.html", org=org, sections=playbook.SECTION_ORDER, can_export_pw=can_export_pw,
                               fonts_unicode=playbook.setup_fonts()["unicode"])

    chosen = {s for s in request.form.getlist("sections") if s in PLAYBOOK_SECTIONS}
    # credentials: "none" (omit section), "list" (usernames/URLs only), "full" (with passwords + 2FA secrets)
    cred_mode = request.form.get("credentials") or "list"
    if cred_mode not in ("none", "list", "full"):
        cred_mode = "list"
    include_pw = cred_mode == "full"
    attach = request.form.get("attach_files") == "1"
    pdf_pw = (request.form.get("pdf_password") or "").strip() or None

    def back(msg):
        flash(msg, "danger")
        return redirect(url_for("org_export", org_id=org.id))

    if include_pw:
        if not can_export_pw:
            log_audit("export_denied", "organization", org.id, org_id=org.id, details="Non-admin attempted a playbook export with passwords")
            return back("Only administrators can export passwords.")
        if not current_user.check_password(request.form.get("confirm_password") or ""):
            log_audit("export_denied", "organization", org.id, org_id=org.id, details="Playbook export with passwords: wrong account password")
            return back("Your account password was incorrect.")
        if not pdf_pw or len(pdf_pw) < 12:
            return back("An export that includes passwords must be protected with a PDF password of at least 12 characters.")
    if cred_mode == "none":
        chosen.discard("passwords")
    else:
        chosen.add("passwords")
    if pdf_pw and len(pdf_pw) < 8:
        return back("The PDF password must be at least 8 characters.")
    if not chosen:
        return back("Select at least one section.")
    if (pdf_pw or attach) and not playbook.pypdf_available():
        return back("Encryption and attachments need the 'pypdf' package (pip install -r requirements.txt).")

    data = collect_playbook_data(org, include_pw)
    logo = BASE_DIR / "static" / "img" / "coresight_logo.png"
    try:
        pdf_bytes, warnings = playbook.build_playbook(data, {
            "sections": chosen, "include_passwords": include_pw, "attach_files": attach and "docs" in chosen,
            "pdf_password": pdf_pw, "logo_path": str(logo) if logo.exists() else None,
            "max_attach_bytes": int(os.environ.get("PLAYBOOK_MAX_ATTACH_MB", 100)) * 1024 * 1024,
        })
    except Exception as e:
        app.logger.exception("Playbook export failed")
        return back(f"Export failed: {type(e).__name__}. Check the server log.")

    log_audit(
        "export_playbook", "organization", org.id, org_id=org.id,
        details=("Exported playbook PDF for '%s' [sections: %s; passwords: %s; attachments: %s; encrypted: %s]" % (
            org.name, ", ".join(sorted(chosen)), "YES" if include_pw else "no", "yes" if attach else "no",
            "yes" if pdf_pw else "no")),
    )
    for w in warnings[:5]:
        flash(w, "warning")

    safe = "".join(c for c in org.name if c.isalnum() or c in (" ", "-", "_")).strip().replace(" ", "_") or "client"
    resp = send_file(io.BytesIO(pdf_bytes), as_attachment=True,
                     download_name=f"{safe}_IT_Playbook_{datetime.utcnow():%Y-%m-%d}.pdf", mimetype="application/pdf")
    resp.headers["Cache-Control"] = "no-store"
    return resp

csrf.exempt(pw_share_open)

# ---------------- Domains ----------------
@app.route("/domains")
@login_required
def domains_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    q = (request.args.get("q") or "").strip()
    qs = Domain.query.filter_by(org_id=org.id)
    if q:
        like = f"%{q}%"
        qs = qs.filter(db.or_(Domain.domain_name.ilike(like), Domain.registrar.ilike(like), Domain.dns_provider.ilike(like)))
    return render_template("domain_list.html", org=org, domains=qs.order_by(Domain.domain_name.asc()).all(), q=q)

@app.route("/domains/new", methods=["GET", "POST"])
@login_required
def domain_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        d = Domain(
            org_id=org.id,
            domain_name=(request.form.get("domain_name") or "").strip().lower(),
            registrar=(request.form.get("registrar") or "").strip() or None,
            dns_provider=(request.form.get("dns_provider") or "").strip() or None,
            nameservers=(request.form.get("nameservers") or "").strip() or None,
            notes=(request.form.get("notes") or "").strip() or None,
        )
        exp = (request.form.get("expires_on") or "").strip()
        if exp:
            try:
                d.expires_on = datetime.strptime(exp, "%Y-%m-%d").date()
            except ValueError:
                flash("Expiry date must be YYYY-MM-DD.", "warning")
        if not d.domain_name:
            flash("Domain name is required.", "warning")
            return render_template("domain_edit.html", org=org, domain=None)
        db.session.add(d)
        db.session.commit()
        flash("Domain added.", "success")
        return redirect(url_for("domain_view", domain_id=d.id))
    return render_template("domain_edit.html", org=org, domain=None)

@app.route("/domains/<int:domain_id>")
@login_required
def domain_view(domain_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    d = db.session.get(Domain, domain_id)
    if not d or d.org_id != org.id:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains_list"))
    dns_snapshot = fetch_dns_snapshot(d.domain_name)
    return render_template("domain_view.html", org=org, domain=d, dns_snapshot=dns_snapshot)

@app.route("/domains/<int:domain_id>/edit", methods=["GET", "POST"])
@login_required
def domain_edit(domain_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    d = db.session.get(Domain, domain_id)
    if not d or d.org_id != org.id:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains_list"))
    if request.method == "POST":
        d.domain_name = (request.form.get("domain_name") or "").strip().lower()
        d.registrar = (request.form.get("registrar") or "").strip() or None
        d.dns_provider = (request.form.get("dns_provider") or "").strip() or None
        d.nameservers = (request.form.get("nameservers") or "").strip() or None
        d.notes = (request.form.get("notes") or "").strip() or None
        exp = (request.form.get("expires_on") or "").strip()
        d.expires_on = None
        if exp:
            try:
                d.expires_on = datetime.strptime(exp, "%Y-%m-%d").date()
            except ValueError:
                flash("Expiry date must be YYYY-MM-DD.", "warning")
        db.session.commit()
        flash("Domain saved.", "success")
        return redirect(url_for("domain_view", domain_id=d.id))
    return render_template("domain_edit.html", org=org, domain=d)

@app.route("/domains/<int:domain_id>/delete", methods=["POST"])
@login_required
def domain_delete(domain_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    d = db.session.get(Domain, domain_id)
    if not d or d.org_id != org.id:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains_list"))
    db.session.delete(d)
    db.session.commit()
    flash("Domain deleted.", "success")
    return redirect(url_for("domains_list"))

@app.route("/domains/lookup", methods=["POST"])
@login_required
def domain_lookup():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    name = (request.form.get("domain_name") or "").strip().lower()
    if not name:
        flash("Enter a domain name first.", "warning")
        return render_template("domain_edit.html", org=org, domain=None)
    try:
        fields = fetch_whois_fields(name)
    except Exception as e:
        flash(f"WHOIS lookup failed: {e}", "danger")
        return render_template("domain_edit.html", org=org, domain={"domain_name": name})
    return render_template("domain_edit.html", org=org, domain={
        "domain_name": name,
        "registrar": fields["registrar"] or "",
        "dns_provider": fields["dns_provider"] or "",
        "nameservers": "\n".join(fields["nameservers"]) if fields["nameservers"] else "",
        "expires_on": fields["expires_on_str"] or "",
        "notes": "",
    })

@app.route("/domains/<int:domain_id>/whois-refresh", methods=["POST"])
@login_required
def domain_whois_refresh(domain_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    d = db.session.get(Domain, domain_id)
    if not d or d.org_id != org.id:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains_list"))
    try:
        fields = fetch_whois_fields(d.domain_name)
    except Exception as e:
        flash(f"WHOIS lookup failed: {e}", "danger")
        return redirect(url_for("domain_view", domain_id=d.id))
    d.registrar = fields.get("registrar")
    d.dns_provider = fields.get("dns_provider")
    ns_list = fields.get("nameservers") or []
    d.nameservers = "\n".join(ns_list) if ns_list else None
    d.expires_on = fields.get("expires_on")
    db.session.commit()
    flash("WHOIS data refreshed.", "success")
    return redirect(url_for("domain_view", domain_id=d.id))

# ---------------- Docs ----------------
@app.route("/docs")
@login_required
def docs():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    folder_id = request.args.get("folder", type=int)
    cur = db.session.get(DocFolder, folder_id) if folder_id else None
    if cur and cur.org_id != org.id:
        flash("Folder not found.", "danger")
        return redirect(url_for("docs"))

    crumbs = []
    f = cur
    while f:
        crumbs.append(f)
        f = f.parent
    crumbs.reverse()

    folders = DocFolder.query.filter_by(
        org_id=org.id,
        parent_id=cur.id if cur else None
    ).order_by(DocFolder.name.asc()).all()

    pages = DocPage.query.filter_by(
        org_id=org.id,
        folder_id=cur.id if cur else None
    ).order_by(DocPage.title.asc()).all()

    files = DocFile.query.filter_by(
        org_id=org.id,
        folder_id=cur.id if cur else None
    ).order_by(DocFile.file_name.asc()).all()

    return render_template(
        "docs_list.html",
        org=org,
        folder=cur,
        breadcrumbs=crumbs,
        folders=folders,
        pages=pages,
        files=files
    )
@app.route("/docs/page/new", methods=["GET", "POST"])
@login_required
def docs_page_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    folder_id = request.values.get("folder_id", type=int)
    folder = db.session.get(DocFolder, folder_id) if folder_id else None
    if folder and folder.org_id != org.id:
        flash("Folder not found.", "danger")
        return redirect(url_for("docs"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        body_html = request.form.get("body_html") or ""

        if not title:
            flash("Title is required.", "warning")
            return render_template("doc_page_edit.html", org=org, row=None, folder=folder, body_html=body_html)

        page = DocPage(
            org_id=org.id,
            folder_id=folder_id,
            title=title,
            body_html=body_html,
            created_by=current_user.id,
            updated_by=current_user.id,
        )
        db.session.add(page)
        db.session.commit()
        flash("Document page created.", "success")
        return redirect(url_for("docs_page_view", page_id=page.id))

    return render_template("doc_page_edit.html", org=org, row=None, folder=folder, body_html="")
@app.route("/docs/page/<int:page_id>")
@login_required
def docs_page_view(page_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    page = db.session.get(DocPage, page_id)
    if not page or page.org_id != org.id:
        flash("Document page not found.", "danger")
        return redirect(url_for("docs"))

    return render_template("doc_page_view.html", org=org, page=page)
@app.route("/docs/page/<int:page_id>/edit", methods=["GET", "POST"])
@login_required
def docs_page_edit(page_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    page = db.session.get(DocPage, page_id)
    if not page or page.org_id != org.id:
        flash("Document page not found.", "danger")
        return redirect(url_for("docs"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        body_html = request.form.get("body_html") or ""
        folder_id = request.form.get("folder_id", type=int)
        folder = db.session.get(DocFolder, folder_id) if folder_id else None

        if folder and folder.org_id != org.id:
            flash("Folder not found.", "danger")
            return redirect(url_for("docs"))

        if not title:
            flash("Title is required.", "warning")
            return render_template("doc_page_edit.html", org=org, row=page, folder=folder, body_html=body_html)

        page.title = title
        page.body_html = body_html
        page.folder_id = folder_id
        page.updated_by = current_user.id
        page.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Document page saved.", "success")
        return redirect(url_for("docs_page_view", page_id=page.id))

    folder = db.session.get(DocFolder, page.folder_id) if page.folder_id else None
    return render_template("doc_page_edit.html", org=org, row=page, folder=folder, body_html=page.body_html or "")
@app.route("/docs/page/<int:page_id>/delete", methods=["POST"])
@login_required
def docs_page_delete(page_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    page = db.session.get(DocPage, page_id)
    if not page or page.org_id != org.id:
        flash("Document page not found.", "danger")
        return redirect(url_for("docs"))

    folder_id = page.folder_id
    db.session.delete(page)
    db.session.commit()
    flash("Document page deleted.", "success")
    return redirect(url_for("docs", folder=folder_id))
@app.route("/docs/upload", methods=["POST"])
@login_required
def docs_upload():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    folder_id = request.form.get("folder_id", type=int)
    file = request.files.get("file")
    notes = request.form.get("notes") or None
    if not file or file.filename == "":
        flash("Choose a file to upload.", "warning")
        return redirect(url_for("docs", folder=folder_id))
    if not allowed_file(file.filename):
        flash("File type not allowed.", "danger")
        return redirect(url_for("docs", folder=folder_id))
    original, stored, size = save_uploaded_file(file, org.id)
    df = DocFile(org_id=org.id, folder_id=folder_id, file_name=original, stored_name=stored,
                 mime_type=file.mimetype or None, size_bytes=size, uploaded_by=current_user.id, notes=notes)
    db.session.add(df)
    db.session.commit()
    flash("File uploaded.", "success")
    return redirect(url_for("docs", folder=folder_id))

@app.route("/docs/file/<int:file_id>")
@login_required
def docs_file_view(file_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    file = db.session.get(DocFile, file_id)
    if not file or file.org_id != org.id:
        flash("File not found.", "danger")
        return redirect(url_for("docs"))
    return render_template("docs_file_view.html", file=file)

@app.route("/docs/file/<int:file_id>/download")
@login_required
def docs_file_download(file_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    file = db.session.get(DocFile, file_id)
    if not file or file.org_id != org.id:
        flash("File not found.", "danger")
        return redirect(url_for("docs"))
    path = org_upload_dir(org.id) / file.stored_name
    return send_file(path, as_attachment=True, download_name=file.file_name, mimetype=file.mime_type or "application/octet-stream")

@app.route("/docs/file/<int:file_id>/delete", methods=["POST"])
@login_required
def docs_file_delete(file_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    file = db.session.get(DocFile, file_id)
    if not file or file.org_id != org.id:
        flash("File not found.", "danger")
        return redirect(url_for("docs"))
    folder_id = file.folder_id
    path = org_upload_dir(org.id) / file.stored_name
    if path.exists():
        path.unlink()
    db.session.delete(file)
    db.session.commit()
    flash("File deleted.", "success")
    return redirect(url_for("docs", folder=folder_id))

@app.route("/docs/folder/<int:folder_id>/delete", methods=["POST"])
@login_required
def docs_folder_delete(folder_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    folder = db.session.get(DocFolder, folder_id)
    if not folder or folder.org_id != org.id:
        flash("Folder not found.", "danger")
        return redirect(url_for("docs"))
    if folder.children or folder.files:
        flash("Folder is not empty.", "warning")
        return redirect(url_for("docs", folder=folder_id))
    parent_id = folder.parent_id
    db.session.delete(folder)
    db.session.commit()
    flash("Folder deleted.", "success")
    return redirect(url_for("docs", folder=parent_id))

@app.route("/org/<int:org_id>/docs/folder/new", methods=["GET", "POST"])
@login_required
def docs_folder_new(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        abort(404)

    if request.method == "POST":
        folder_name = (request.form.get("folder_name") or "").strip()
        parent_id = request.form.get("parent_id", type=int)

        if not folder_name:
            flash("Folder name is required.", "danger")
            return redirect(url_for("docs_folder_new", org_id=org_id))

        parent = db.session.get(DocFolder, parent_id) if parent_id else None
        if parent and parent.org_id != org_id:
            flash("Parent folder not found.", "danger")
            return redirect(url_for("docs", folder=parent_id))

        folder = DocFolder(
            org_id=org_id,
            name=folder_name,
            parent_id=parent_id
        )
        db.session.add(folder)
        db.session.commit()

        flash("Folder created successfully.", "success")
        return redirect(url_for("docs", folder=parent_id))

    parent_id = request.args.get("parent_id", type=int)
    return render_template("docs_folder_new.html", org=org, org_id=org_id, parent_id=parent_id)
# ---------------- Contacts ----------------
@app.route("/contacts")
@login_required
def contacts_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    q = (request.args.get("q") or "").strip()
    qs = SiteContact.query.filter_by(org_id=org.id)
    if q:
        like = f"%{q}%"
        qs = qs.filter(db.or_(SiteContact.first_name.ilike(like), SiteContact.last_name.ilike(like), SiteContact.email.ilike(like), SiteContact.position.ilike(like)))
    return render_template("contacts_list.html", org=org, contacts=qs.order_by(SiteContact.last_name.asc(), SiteContact.first_name.asc()).all(), q=q)

@app.route("/contacts/new", methods=["GET", "POST"])
@login_required
def contact_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        c = SiteContact(
            org_id=org.id,
            first_name=(request.form.get("first_name") or "").strip(),
            last_name=(request.form.get("last_name") or "").strip(),
            email=(request.form.get("email") or "").strip() or None,
            mobile=(request.form.get("mobile") or "").strip() or None,
            office=(request.form.get("office") or "").strip() or None,
            position=(request.form.get("position") or "").strip() or None,
            is_decision_maker=True if request.form.get("is_decision_maker") == "on" else False,
            notes=(request.form.get("notes") or "").strip() or None,
        )
        if not c.first_name or not c.last_name:
            flash("First and last name are required.", "warning")
            return render_template("contact_edit.html", org=org, contact=None)
        db.session.add(c)
        db.session.commit()
        flash("Contact added.", "success")
        return redirect(url_for("contact_view", contact_id=c.id))
    return render_template("contact_edit.html", org=org, contact=None)

@app.route("/contacts/<int:contact_id>")
@login_required
def contact_view(contact_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    c = db.session.get(SiteContact, contact_id)
    if not c or c.org_id != org.id:
        flash("Contact not found.", "danger")
        return redirect(url_for("contacts_list"))
    return render_template("contact_view.html", org=org, contact=c)

@app.route("/contacts/<int:contact_id>/edit", methods=["GET", "POST"])
@login_required
def contact_edit(contact_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    c = db.session.get(SiteContact, contact_id)
    if not c or c.org_id != org.id:
        flash("Contact not found.", "danger")
        return redirect(url_for("contacts_list"))
    if request.method == "POST":
        c.first_name = (request.form.get("first_name") or "").strip()
        c.last_name = (request.form.get("last_name") or "").strip()
        c.email = (request.form.get("email") or "").strip() or None
        c.mobile = (request.form.get("mobile") or "").strip() or None
        c.office = (request.form.get("office") or "").strip() or None
        c.position = (request.form.get("position") or "").strip() or None
        c.is_decision_maker = True if request.form.get("is_decision_maker") == "on" else False
        c.notes = (request.form.get("notes") or "").strip() or None
        db.session.commit()
        flash("Contact saved.", "success")
        return redirect(url_for("contact_view", contact_id=c.id))
    return render_template("contact_edit.html", org=org, contact=c)

@app.route("/contacts/<int:contact_id>/delete", methods=["POST"])
@login_required
def contact_delete(contact_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    c = db.session.get(SiteContact, contact_id)
    if not c or c.org_id != org.id:
        flash("Contact not found.", "danger")
        return redirect(url_for("contacts_list"))
    db.session.delete(c)
    db.session.commit()
    flash("Contact deleted.", "success")
    return redirect(url_for("contacts_list"))

# ---------------- Sites ----------------
@app.route("/sites")
@login_required
def sites_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    rows = SiteAddress.query.filter_by(org_id=org.id).order_by(SiteAddress.site_name.asc()).all()
    return render_template("sites_list.html", org=org, sites=rows)

@app.route("/sites/new", methods=["GET", "POST"])
@login_required
def site_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        s = SiteAddress(
            org_id=org.id,
            site_name=(request.form.get("site_name") or "").strip(),
            address1=(request.form.get("address1") or "").strip(),
            address2=(request.form.get("address2") or "").strip() or None,
            suburb=(request.form.get("suburb") or "").strip() or None,
            state=(request.form.get("state") or "").strip() or None,
            postcode=(request.form.get("postcode") or "").strip() or None,
            country=(request.form.get("country") or "").strip() or "Australia",
            notes=(request.form.get("notes") or "").strip() or None
        )
        if not s.site_name or not s.address1:
            flash("Site name and Address 1 are required.", "warning")
            return render_template("site_edit.html", org=org, site=None)
        db.session.add(s)
        db.session.commit()
        flash("Site added.", "success")
        return redirect(url_for("site_view", site_id=s.id))
    return render_template("site_edit.html", org=org, site=None)

@app.route("/sites/<int:site_id>")
@login_required
def site_view(site_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    s = db.session.get(SiteAddress, site_id)
    if not s or s.org_id != org.id:
        flash("Site not found.", "danger")
        return redirect(url_for("sites_list"))
    return render_template("site_view.html", org=org, site=s)

@app.route("/sites/<int:site_id>/edit", methods=["GET", "POST"])
@login_required
def site_edit(site_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    s = db.session.get(SiteAddress, site_id)
    if not s or s.org_id != org.id:
        flash("Site not found.", "danger")
        return redirect(url_for("sites_list"))
    if request.method == "POST":
        s.site_name = (request.form.get("site_name") or "").strip()
        s.address1 = (request.form.get("address1") or "").strip()
        s.address2 = (request.form.get("address2") or "").strip() or None
        s.suburb = (request.form.get("suburb") or "").strip() or None
        s.state = (request.form.get("state") or "").strip() or None
        s.postcode = (request.form.get("postcode") or "").strip() or None
        s.country = (request.form.get("country") or "").strip() or "Australia"
        s.notes = (request.form.get("notes") or "").strip() or None
        db.session.commit()
        flash("Site saved.", "success")
        return redirect(url_for("site_view", site_id=s.id))
    return render_template("site_edit.html", org=org, site=s)

@app.route("/sites/<int:site_id>/delete", methods=["POST"])
@login_required
def site_delete(site_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    s = db.session.get(SiteAddress, site_id)
    if not s or s.org_id != org.id:
        flash("Site not found.", "danger")
        return redirect(url_for("sites_list"))
    db.session.delete(s)
    db.session.commit()
    flash("Site deleted.", "success")
    return redirect(url_for("sites_list"))

# ---------------- Network ----------------
@app.route("/network")
@login_required
def network_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    devices = NetworkDevice.query.filter_by(org_id=org.id).order_by(NetworkDevice.device_name.asc()).all()
    return render_template("network_list.html", org=org, devices=devices)

@app.route("/network/new", methods=["GET", "POST"])
@login_required
def network_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    if request.method == "POST":
        d = NetworkDevice(
            org_id=org.id,
            device_name=(request.form.get("device_name") or "").strip(),
            ip_address=(request.form.get("ip_address") or "").strip() or None,
            mac_address=(request.form.get("mac_address") or "").strip() or None,
            notes=(request.form.get("notes") or "").strip() or None
        )
        if not d.device_name:
            flash("Device name is required.", "warning")
            return render_template("network_edit.html", org=org, device=None)
        db.session.add(d)
        db.session.commit()
        flash("Network device added.", "success")
        return redirect(url_for("network_list"))
    return render_template("network_edit.html", org=org, device=None)

# ---------------- Assets ----------------
@app.route("/assets")
@login_required
def assets():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    rows = Asset.query.filter_by(org_id=org.id).order_by(Asset.device_name.asc()).all()
    return render_template("assets_list.html", org=org, assets=rows)

@app.route("/assets/new", methods=["GET", "POST"])
@login_required
def assets_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    device_types = [t.name for t in AssetType.query.order_by(AssetType.name.asc()).all()]
    brands = [b.name for b in AssetBrand.query.order_by(AssetBrand.name.asc()).all()]
    if request.method == "POST":
        a = Asset(
            org_id=org.id,
            device_name=(request.form.get("device_name") or "").strip(),
            device_type=request.form.get("device_type") or None,
            brand=request.form.get("brand") or None,
            serial_number=(request.form.get("serial_number") or "").strip() or None,
            asset_id=(request.form.get("asset_id") or "").strip() or None,
            location=(request.form.get("location") or "").strip() or None,
            issued_to=(request.form.get("issued_to") or "").strip() or None,
            notes=(request.form.get("notes") or "").strip() or None,
        )
        dp = (request.form.get("date_purchased") or "").strip()
        if dp:
            try:
                a.date_purchased = datetime.strptime(dp, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid purchase date.", "warning")
        wd = (request.form.get("warranty_expires") or "").strip()
        if wd:
            try:
                a.warranty_expires = datetime.strptime(wd, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid warranty date.", "warning")
        if not a.device_name:
            flash("Device name required.", "warning")
            return render_template("asset_edit.html", org=org, asset=None, device_types=device_types, brands=brands)
        db.session.add(a)
        db.session.commit()
        flash("Asset created.", "success")
        return redirect(url_for("asset_view", asset_id=a.id))
    return render_template("asset_edit.html", org=org, asset=None, device_types=device_types, brands=brands)

@app.route("/assets/<int:asset_id>/view")
@login_required
def asset_view(asset_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    a = db.session.get(Asset, asset_id)
    if not a or a.org_id != org.id:
        flash("Asset not found.", "danger")
        return redirect(url_for("assets"))
    return render_template("asset_view.html", org=org, asset=a)

@app.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
def asset_edit(asset_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    a = db.session.get(Asset, asset_id)
    if not a or a.org_id != org.id:
        flash("Asset not found.", "danger")
        return redirect(url_for("assets"))
    device_types = [t.name for t in AssetType.query.order_by(AssetType.name.asc()).all()]
    brands = [b.name for b in AssetBrand.query.order_by(AssetBrand.name.asc()).all()]
    if request.method == "POST":
        a.device_name = (request.form.get("device_name") or "").strip()
        a.device_type = request.form.get("device_type") or None
        a.brand = request.form.get("brand") or None
        a.serial_number = (request.form.get("serial_number") or "").strip() or None
        a.asset_id = (request.form.get("asset_id") or "").strip() or None
        a.location = (request.form.get("location") or "").strip() or None
        a.issued_to = (request.form.get("issued_to") or "").strip() or None
        a.notes = (request.form.get("notes") or "").strip() or None
        dp = (request.form.get("date_purchased") or "").strip()
        a.date_purchased = None
        if dp:
            try:
                a.date_purchased = datetime.strptime(dp, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid purchase date.", "warning")
        wd = (request.form.get("warranty_expires") or "").strip()
        a.warranty_expires = None
        if wd:
            try:
                a.warranty_expires = datetime.strptime(wd, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid warranty date.", "warning")
        db.session.commit()
        flash("Asset saved.", "success")
        return redirect(url_for("asset_view", asset_id=a.id))
    return render_template("asset_edit.html", org=org, asset=a, device_types=device_types, brands=brands)

@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def asset_delete(asset_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    a = db.session.get(Asset, asset_id)
    if not a or a.org_id != org.id:
        flash("Asset not found.", "danger")
        return redirect(url_for("assets"))
    db.session.delete(a)
    db.session.commit()
    flash("Asset deleted.", "success")
    return redirect(url_for("assets"))

# ---------------- Admin ----------------
@app.route("/admin/users")
@login_required
def admin_users():
    super_admin_only()
    users = User.query.order_by(User.email.asc()).all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
def admin_users_new():
    super_admin_only()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        role = request.form.get("role") or "tech"
        form = {"email": email, "role": role}

        if not email:
            flash("Email is required.", "warning")
            return render_template("admin_users_new.html", roles=ROLES, form=form)
        if pw and not password_meets_policy(pw):
            flash("Password must be at least 10 characters and use 3 of: upper case, lower case, numbers, symbols.", "warning")
            return render_template("admin_users_new.html", roles=ROLES, form=form)
        if User.query.filter_by(email=email).first():
            flash("User already exists.", "warning")
            return render_template("admin_users_new.html", roles=ROLES, form=form)

        u = User(email=email, must_change_password=bool(pw))
        apply_role(u, role)
        # No password typed: give the account a random one nobody knows; the user sets their own via the link.
        u.set_password(pw or secrets.token_urlsafe(32))
        db.session.add(u)
        db.session.commit()
        log_audit("create", "user", u.id, details=f"Created user: {u.email} ({'temporary password' if pw else 'set-password link'})",
                  user_id=current_user.id)

        login_url = url_for("login", _external=True)
        if pw:
            # Never email the password itself: the admin passes it on separately.
            body = (f"Hello,\n\nA CoreSight Vault account has been created for you.\n\nSign in at: {login_url}\n"
                    f"Username: {u.email}\n\nYour administrator will give you a temporary password separately. "
                    f"You'll be asked to choose your own password when you first sign in.\n\n"
                    f"If you weren't expecting this, please contact your administrator.\n\nCoreSight Vault\n")
        else:
            link = url_for("reset_password", token=generate_reset_token(u, welcome=True), _external=True)
            body = (f"Hello,\n\nA CoreSight Vault account has been created for you.\n\n"
                    f"Choose your password using this link (it works once and expires in {WELCOME_LINK_MAX_AGE // 3600} hours):\n{link}\n\n"
                    f"Then sign in at: {login_url}\nUsername: {u.email}\n\n"
                    f"If you weren't expecting this, please contact your administrator.\n\nCoreSight Vault\n")
        try:
            send_email(u.email, "Welcome to CoreSight Vault", body)
            flash("User created and welcome email sent." + ("" if not pw else " Give them the temporary password separately."), "success")
        except Exception as e:
            app.logger.warning("Welcome email failed: %s", e)
            if pw:
                flash(f"User created, but the welcome email failed ({e}). Give them the temporary password yourself.", "warning")
            else:
                # Show the link once so the admin can pass it on another way.
                return render_template("admin_users_new.html", roles=ROLES, form={}, created=u, link=link, email_error=str(e))
        return redirect(url_for("admin_users"))

    return render_template("admin_users_new.html", roles=ROLES, form={})

@app.route("/admin/smtp", methods=["GET", "POST"])
@login_required
def admin_smtp():
    super_admin_only()
    settings = get_smtp_settings()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save":
            settings.host = (request.form.get("host") or "").strip() or None
            settings.port = int(request.form.get("port") or 587)
            settings.username = (request.form.get("username") or "").strip() or None
            settings.from_email = (request.form.get("from_email") or "").strip() or None
            settings.use_tls = True if request.form.get("use_tls") == "on" else False
            settings.use_ssl = True if request.form.get("use_ssl") == "on" else False
            new_password = (request.form.get("password") or "").strip()
            if new_password:
                settings.password = new_password
            db.session.commit()
            flash("SMTP settings saved.", "success")
            return redirect(url_for("admin_smtp"))
        elif action == "test":
            test_to = (request.form.get("test_to") or "").strip()
            try:
                send_email(test_to, "CoreSight Vault SMTP Test", "This is a test email from CoreSight Vault.")
                flash("Test email sent successfully.", "success")
            except Exception as e:
                flash(f"SMTP test failed: {e}", "danger")
            return redirect(url_for("admin_smtp"))
    return render_template("admin_smtp.html", settings=settings)

@app.route("/admin/assets-config", methods=["GET", "POST"])
@login_required
def admin_assets_config():
    super_admin_only()
    if request.method == "POST":
        type_name = (request.form.get("type_name") or "").strip()
        brand_name = (request.form.get("brand_name") or "").strip()
        if type_name and not AssetType.query.filter_by(name=type_name).first():
            db.session.add(AssetType(name=type_name))
        if brand_name and not AssetBrand.query.filter_by(name=brand_name).first():
            db.session.add(AssetBrand(name=brand_name))
        db.session.commit()
        flash("Asset config updated.", "success")
        return redirect(url_for("admin_assets_config"))
    return render_template("admin_assets_config.html", types=AssetType.query.order_by(AssetType.name.asc()).all(), brands=AssetBrand.query.order_by(AssetBrand.name.asc()).all())

@app.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
def admin_user_toggle_active(user_id):
    super_admin_only()

    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    if user.id == current_user.id:
        flash("You cannot disable your own account.", "warning")
        return redirect(url_for("admin_users"))

    user.is_active_user = not user.is_active_user
    db.session.commit()

    flash("User updated.", "success")
    return redirect(url_for("admin_users"))

# ---------------- Dashboard / Audit / Asset Extensions ----------------
@app.route("/dashboard/data")
@login_required
def dashboard_data():
    org = require_active_org()
    if not org:
        return jsonify({"error": "no active org"}), 400
    return jsonify(get_dashboard_data(org.id))

@app.route("/audit/logs")
@login_required
def audit_logs():
    org = active_org()
    qs = AuditLog.query
    if org:
        qs = qs.filter(db.or_(AuditLog.org_id == org.id, AuditLog.org_id.is_(None)))
    rows = qs.order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify({
        "results": [
            {
                "id": r.id,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "action": r.action,
                "entity_type": r.entity_type,
                "entity_id": r.entity_id,
                "details": r.details or "",
                "user_id": r.user_id,
                "org_id": r.org_id,
            }
            for r in rows
        ]
    })

@app.route("/assets/<int:asset_id>/assignment", methods=["GET", "POST"])
@login_required
def asset_assignment(asset_id):
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))

    asset = db.session.get(Asset, asset_id)
    if not asset or asset.org_id != org.id:
        return jsonify({"error": "asset not found"}), 404

    assignment = get_asset_assignment(asset_id)

    if request.method == "GET":
        return jsonify({
            "asset_id": asset.id,
            "asset_name": asset.device_name,
            "assignment": {
                "site_id": assignment.site_id if assignment else None,
                "contact_id": assignment.contact_id if assignment else None,
                "status": assignment.status if assignment else "active",
                "notes": assignment.notes if assignment else "",
            }
        })

    site_id = request.form.get("site_id", type=int)
    contact_id = request.form.get("contact_id", type=int)
    status = (request.form.get("status") or "active").strip()
    notes = (request.form.get("notes") or "").strip() or None

    if site_id:
        site = db.session.get(SiteAddress, site_id)
        if not site or site.org_id != org.id:
            return jsonify({"error": "invalid site"}), 400

    if contact_id:
        contact = db.session.get(SiteContact, contact_id)
        if not contact or contact.org_id != org.id:
            return jsonify({"error": "invalid contact"}), 400

    if assignment is None:
        assignment = AssetAssignment(asset_id=asset.id)
        db.session.add(assignment)

    assignment.site_id = site_id
    assignment.contact_id = contact_id
    assignment.status = status
    assignment.notes = notes
    assignment.updated_by = current_user.id
    db.session.commit()

    log_audit("assign", "asset", asset.id, org_id=org.id, details=f"Updated asset assignment/status to {status}")
    return jsonify({"success": True})

#------+Search-------
@app.route("/search/global")
@login_required
def global_search():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"results": []})

    def org_name(org_id):
        org = db.session.get(Organization, org_id)
        return org.name if org else "Unknown organisation"

    results = []

    org_rows = Organization.query.filter(
        db.or_(
            Organization.name.ilike(f"%{q}%"),
            Organization.description.ilike(f"%{q}%")
        )
    ).limit(15).all()

    for row in org_rows:
        results.append({
            "type": "Organisation",
            "title": row.name,
            "subtitle": row.description or "",
            "snippet": _snippet(row.description or "", q),
            "org_name": row.name,
            "url": url_for("org_view", org_id=row.id),
        })

    pw_rows = Password.query.filter(
        db.or_(
            Password.name.ilike(f"%{q}%"),
            Password.url.ilike(f"%{q}%"),
            Password.notes.ilike(f"%{q}%"),
            Password.folder.ilike(f"%{q}%"),
            Password.tags.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in pw_rows:
        results.append({
            "type": "Password",
            "title": row.name,
            "subtitle": decrypt_secret(row.username_plain) or row.url or "",
            "snippet": _snippet((row.notes or "") + " " + (row.url or ""), q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('pw_view', pw_id=row.id)}",
        })

    domain_rows = Domain.query.filter(
        db.or_(
            Domain.domain_name.ilike(f"%{q}%"),
            Domain.registrar.ilike(f"%{q}%"),
            Domain.dns_provider.ilike(f"%{q}%"),
            Domain.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in domain_rows:
        results.append({
            "type": "Domain",
            "title": row.domain_name,
            "subtitle": row.registrar or row.dns_provider or "",
            "snippet": _snippet(row.notes or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('domain_view', domain_id=row.id)}",
        })

    contact_rows = SiteContact.query.filter(
        db.or_(
            SiteContact.first_name.ilike(f"%{q}%"),
            SiteContact.last_name.ilike(f"%{q}%"),
            SiteContact.email.ilike(f"%{q}%"),
            SiteContact.mobile.ilike(f"%{q}%"),
            SiteContact.office.ilike(f"%{q}%"),
            SiteContact.position.ilike(f"%{q}%"),
            SiteContact.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in contact_rows:
        results.append({
            "type": "Contact",
            "title": f"{row.first_name} {row.last_name}".strip(),
            "subtitle": row.email or row.position or "",
            "snippet": _snippet(row.notes or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('contact_view', contact_id=row.id)}",
        })

    site_rows = SiteAddress.query.filter(
        db.or_(
            SiteAddress.site_name.ilike(f"%{q}%"),
            SiteAddress.address1.ilike(f"%{q}%"),
            SiteAddress.address2.ilike(f"%{q}%"),
            SiteAddress.suburb.ilike(f"%{q}%"),
            SiteAddress.state.ilike(f"%{q}%"),
            SiteAddress.postcode.ilike(f"%{q}%"),
            SiteAddress.country.ilike(f"%{q}%"),
            SiteAddress.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in site_rows:
        results.append({
            "type": "Site",
            "title": row.site_name,
            "subtitle": ", ".join(filter(None, [row.suburb, row.state, row.postcode])),
            "snippet": _snippet(" ".join(filter(None, [row.address1, row.address2, row.notes])), q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('site_view', site_id=row.id)}",
        })

    network_rows = NetworkDevice.query.filter(
        db.or_(
            NetworkDevice.device_name.ilike(f"%{q}%"),
            NetworkDevice.ip_address.ilike(f"%{q}%"),
            NetworkDevice.mac_address.ilike(f"%{q}%"),
            NetworkDevice.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in network_rows:
        results.append({
            "type": "Network",
            "title": row.device_name,
            "subtitle": row.ip_address or row.mac_address or "",
            "snippet": _snippet(row.notes or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id),
        })

    asset_rows = Asset.query.filter(
        db.or_(
            Asset.device_name.ilike(f"%{q}%"),
            Asset.device_type.ilike(f"%{q}%"),
            Asset.brand.ilike(f"%{q}%"),
            Asset.serial_number.ilike(f"%{q}%"),
            Asset.asset_id.ilike(f"%{q}%"),
            Asset.location.ilike(f"%{q}%"),
            Asset.issued_to.ilike(f"%{q}%"),
            Asset.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in asset_rows:
        results.append({
            "type": "Asset",
            "title": row.device_name,
            "subtitle": row.serial_number or row.asset_id or row.device_type or "",
            "snippet": _snippet(row.notes or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('asset_view', asset_id=row.id)}",
        })

    doc_files = DocFile.query.filter(
        db.or_(
            DocFile.file_name.ilike(f"%{q}%"),
            DocFile.notes.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in doc_files:
        results.append({
            "type": "File",
            "title": row.file_name,
            "subtitle": "Uploaded file",
            "snippet": _snippet(row.notes or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('docs_file_view', file_id=row.id)}",
        })

    page_rows = DocPage.query.filter(
        db.or_(
            DocPage.title.ilike(f"%{q}%"),
            DocPage.body_html.ilike(f"%{q}%"),
        )
    ).limit(20).all()

    for row in page_rows:
        results.append({
            "type": "Document",
            "title": row.title,
            "subtitle": "Rich text document",
            "snippet": _snippet(row.body_html or "", q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('docs_page_view', page_id=row.id)}",
        })

    rec_rows = CustomRecord.query.filter(db.or_(
        CustomRecord.name.ilike(f"%{q}%"), CustomRecord.data_json.ilike(f"%{q}%"))).limit(20).all()
    for row in rec_rows:
        plain_keys = [f["key"] for f in row.ctype.fields if f["type"] != "password"]
        text_blob = " ".join(str(row.data.get(k, "")) for k in plain_keys)
        results.append({
            "type": row.ctype.name,
            "title": row.name,
            "subtitle": "",
            "snippet": _snippet(text_blob, q),
            "org_name": org_name(row.org_id),
            "url": url_for("org_view", org_id=row.org_id) + f"?next={url_for('record_view', rid=row.id)}",
        })

    results = sorted(results, key=lambda x: (x["type"], x["title"].lower()))
    return jsonify({"results": results[:75]})


# ---------------- Init ----------------
def seed_defaults():
    if not AssetType.query.first():
        db.session.add_all([
            AssetType(name="Laptop"), AssetType(name="Desktop"), AssetType(name="Server"),
            AssetType(name="Router"), AssetType(name="Switch"), AssetType(name="Printer"),
            AssetType(name="Firewall"), AssetType(name="Phone")
        ])
    if not AssetBrand.query.first():
        db.session.add_all([
            AssetBrand(name="Dell"), AssetBrand(name="HP"), AssetBrand(name="Lenovo"),
            AssetBrand(name="Ubiquiti"), AssetBrand(name="MikroTik"), AssetBrand(name="Brother"),
            AssetBrand(name="DrayTek"), AssetBrand(name="Apple")
        ])
    if not SMTPSettings.query.first():
        db.session.add(SMTPSettings())
    if not User.query.first():
        u = User(email="admin@local", is_admin=True, is_super_admin=True, role="admin", must_change_password=True)
        u.set_password("admin")
        db.session.add(u)
    db.session.commit()

SCHEMA_ADDITIONS = [
    ("password_share_link", "note", "VARCHAR(500)"),
    ("password_share_link", "revoked_at", "DATETIME"),
    ("password_share_link", "opened_ip", "VARCHAR(64)"),
    ("user", "role", "VARCHAR(20)"),
    ("asset", "warranty_expires", "DATE"),
    ("password", "folder", "VARCHAR(100)"),
    ("password", "tags", "VARCHAR(500)"),
    ("password", "rotate_days", "INTEGER"),
    ("password", "password_changed_at", "DATETIME"),
]

def ensure_columns():
    """create_all() won't add columns to existing tables, so add any that are missing."""
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    for table, col, ddl in SCHEMA_ADDITIONS:
        if not insp.has_table(table):
            continue
        if col not in {c["name"] for c in insp.get_columns(table)}:
            db.session.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {col} {ddl}'))
    db.session.execute(text(
        "UPDATE \"user\" SET role = CASE WHEN is_super_admin OR is_admin THEN 'admin' ELSE 'tech' END WHERE role IS NULL"))
    db.session.commit()

# ---------------- Feature modules ----------------
from types import SimpleNamespace
import records, ops

_ns = SimpleNamespace(**{k: v for k, v in globals().items() if not k.startswith("__")})
records.init(_ns)
ops.init(_ns)
links_for = _ns.links_for   # used by collect_playbook_data (resolved at call time)

def _startup():
    """Create/upgrade the schema and seed defaults.

    Several gunicorn workers import this module at the same moment; on a brand-new
    database they would all try to create tables and seed rows together and crash
    (UNIQUE constraint failed). A file lock makes them take turns: the first does
    the work, the rest find it already done.
    """
    import hashlib, tempfile
    lock_name = "coresight-startup-" + hashlib.sha1(app.config["SQLALCHEMY_DATABASE_URI"].encode()).hexdigest()[:12] + ".lock"
    try:
        import fcntl   # Linux/macOS (production); Windows dev runs a single process anyway
    except ImportError:
        fcntl = None
    with open(os.path.join(tempfile.gettempdir(), lock_name), "w") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            with app.app_context():
                db.create_all()
                ensure_columns()
                seed_defaults()
        finally:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_UN)

_startup()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=os.environ.get("FLASK_DEBUG") == "1")
