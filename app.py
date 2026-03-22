
import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, date
from pathlib import Path

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

try:
    import whois as pywhois
except Exception:
    pywhois = None

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads"
UPLOAD_ROOT.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-now")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'coresight.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))
app.config["RESET_TOKEN_SALT"] = "password-reset-salt"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTS = {"pdf","doc","docx","xls","xlsx","ppt","pptx","txt","jpg","jpeg","png","gif","webp"}

# ---------------- Models ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_totp_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

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
    notes = db.Column(db.Text, nullable=True)

class SMTPSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=True)
    port = db.Column(db.Integer, default=587)
    username = db.Column(db.String(255), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    from_email = db.Column(db.String(255), nullable=True)
    use_tls = db.Column(db.Boolean, default=True)
    use_ssl = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ---------------- Helpers ----------------
def active_org():
    org_id = session.get("active_org_id")
    return db.session.get(Organization, org_id) if org_id else None

@app.context_processor
def inject_globals():
    return {"active_org": active_org()}

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

def generate_reset_token(email):
    return serializer().dumps(email, salt=app.config["RESET_TOKEN_SALT"])

def verify_reset_token(token, max_age=3600):
    try:
        return serializer().loads(token, salt=app.config["RESET_TOKEN_SALT"], max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

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
        login_user(user)
        return redirect(url_for("orgs"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
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
                token = generate_reset_token(user.email)
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
    email = verify_reset_token(token)
    if not email:
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Invalid reset request.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        if pw != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("reset_password.html")
        if not password_meets_policy(pw):
            flash("Password does not meet complexity policy.", "warning")
            return render_template("reset_password.html")
        user.set_password(pw)
        user.must_change_password = False
        user.failed_logins = 0
        user.locked_until = None
        db.session.commit()
        flash("Password reset complete.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/account")
@login_required
def account():
    return render_template("account.html")

@app.route("/setup-2fa")
@login_required
def setup_2fa():
    return render_template("setup_2fa.html")

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
    return render_template("org_view.html", org=org)

# ---------------- Passwords ----------------
@app.route("/passwords")
@login_required
def pw_list():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    rows = Password.query.filter_by(org_id=org.id).order_by(Password.name.asc()).all()
    return render_template("pw_list.html", org=org, passwords=rows)

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
            username_plain=request.form.get("username") or None,
            password_plain=request.form.get("password") or None,
            url=request.form.get("url") or None,
            notes=request.form.get("notes") or None,
            otp_secret=(request.form.get("otp_secret") or "").strip() or None,
            updated_at=datetime.utcnow(),
            updated_by=current_user.id
        )
        if not p.name:
            flash("Name required.", "warning")
            return render_template("pw_edit.html", org=org, row=None)
        db.session.add(p)
        db.session.commit()
        flash("Password created.", "success")
        return redirect(url_for("pw_view", pw_id=p.id))
    return render_template("pw_edit.html", org=org, row=None)

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
        row.name = (request.form.get("name") or "").strip()
        row.username_plain = request.form.get("username") or None
        row.password_plain = request.form.get("password") or None
        row.url = request.form.get("url") or None
        row.notes = request.form.get("notes") or None
        row.otp_secret = (request.form.get("otp_secret") or "").strip() or None
        row.updated_at = datetime.utcnow()
        row.updated_by = current_user.id
        if not row.name:
            flash("Name required.", "warning")
            return render_template("pw_edit.html", org=org, row=row)
        db.session.commit()
        flash("Password updated.", "success")
        return redirect(url_for("pw_view", pw_id=row.id))
    return render_template("pw_edit.html", org=org, row=row)

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
    return render_template("pw_view.html", org=org, row=row, history=history)

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
    db.session.delete(row)
    db.session.commit()
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
    return jsonify({"username": row.username_plain or "", "password": row.password_plain or ""})

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
    return render_template("domain_view.html", org=org, domain=d)

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
    folders = DocFolder.query.filter_by(org_id=org.id, parent_id=cur.id if cur else None).order_by(DocFolder.name.asc()).all()
    files = DocFile.query.filter_by(org_id=org.id, folder_id=cur.id if cur else None).order_by(DocFile.file_name.asc()).all()
    return render_template("docs_list.html", org=org, folder=cur, breadcrumbs=crumbs, folders=folders, files=files)

@app.route("/docs/folder/new", methods=["POST"])
@login_required
def docs_folder_new():
    org = require_active_org()
    if not org:
        return redirect(url_for("orgs"))
    name = (request.form.get("name") or "").strip()
    parent_id = request.form.get("parent_id", type=int)
    if not name:
        flash("Folder name required.", "warning")
        return redirect(url_for("docs", folder=parent_id))
    folder = DocFolder(org_id=org.id, name=name, parent_id=parent_id or None)
    db.session.add(folder)
    db.session.commit()
    flash("Folder created.", "success")
    return redirect(url_for("docs", folder=parent_id))

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
        is_admin = True if request.form.get("is_admin") else False
        is_super_admin = True if request.form.get("is_super_admin") else False
        if not email or not pw:
            flash("Email and password required.", "warning")
            return render_template("admin_users_new.html")
        if not password_meets_policy(pw):
            flash("Password does not meet policy.", "warning")
            return render_template("admin_users_new.html")
        if User.query.filter_by(email=email).first():
            flash("User already exists.", "warning")
            return render_template("admin_users_new.html")
        u = User(email=email, is_admin=is_admin, is_super_admin=is_super_admin, must_change_password=True)
        u.set_password(pw)
        db.session.add(u)
        db.session.commit()
        flash("User created.", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin_users_new.html")

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
        u = User(email="admin@local", is_admin=True, is_super_admin=True)
        u.set_password("admin")
        db.session.add(u)
    db.session.commit()

with app.app_context():
    db.create_all()
    seed_defaults()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
