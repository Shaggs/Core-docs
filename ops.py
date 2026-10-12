"""
Operational features: expiry tracking + email alerts, the audit log viewer, and the backups page.
Registered from app.py with ops.init(ctx).
"""
import csv
import io
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from sqlalchemy import event
from flask import (render_template, request, redirect, url_for, flash, abort, Response, send_file)

import backup as backup_lib

_CTX = None
DEFAULT_DAYS = "60,30,14,7,1"
SOON_DAYS = 30   # "expiring soon" = within this many days (badge + expiring page summary)


# ---------------------------------------------------------------------------- expiry data
def parse_days(text):
    vals = set()
    for part in re.split(r"[,\s]+", text or ""):
        if part.isdigit() and 0 < int(part) <= 730:
            vals.add(int(part))
    return sorted(vals)


def parse_recipients(text):
    out = []
    for part in re.split(r"[,;\s]+", text or ""):
        part = part.strip()
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", part) and part.lower() not in [o.lower() for o in out]:
            out.append(part)
    return out


def get_settings():
    C = _CTX
    st = C.AlertSetting.query.first()
    if not st:
        st = C.AlertSetting(enabled=False, recipients="", days=DEFAULT_DAYS)
        C.db.session.add(st)
        C.db.session.commit()
    return st


def collect_expiring(today=None, org_id=None):
    """Every dated item that can expire: domains, asset warranties, and custom date fields flagged for alerts."""
    C = _CTX
    today = today or date.today()
    orgs = {o.id: o.name for o in C.Organization.query.all()}
    items = []

    def add(kind, name, oid, when, key, endpoint, args):
        if not when or (org_id and oid != org_id) or oid not in orgs:
            return
        items.append({"kind": kind, "name": name, "org_id": oid, "org": orgs[oid], "date": when,
                      "days": (when - today).days, "key": f"{key}:{when.isoformat()}",
                      "endpoint": endpoint, "args": args})

    for d in C.Domain.query.filter(C.Domain.expires_on.isnot(None)).all():
        add("Domain", d.domain_name, d.org_id, d.expires_on, f"domain:{d.id}", "domain_view", {"domain_id": d.id})
    for a in C.Asset.query.filter(C.Asset.warranty_expires.isnot(None)).all():
        add("Warranty", a.device_name, a.org_id, a.warranty_expires, f"warranty:{a.id}", "asset_view", {"asset_id": a.id})
    for p in C.Password.query.filter(C.Password.rotate_days.isnot(None)).all():
        add("Password rotation", p.name, p.org_id, p.rotation_due_on, f"rotate:{p.id}", "pw_view", {"pw_id": p.id})
    for t in C.CustomType.query.all():
        fields = [f for f in t.fields if f.get("type") == "date" and f.get("alert")]
        if not fields:
            continue
        for r in C.CustomRecord.query.filter_by(type_id=t.id).all():
            data = r.data
            for f in fields:
                try:
                    when = datetime.strptime(data.get(f["key"], ""), "%Y-%m-%d").date()
                except ValueError:
                    continue
                add(f"{t.name}: {f['label']}", r.name, r.org_id, when, f"rec:{r.id}:{f['key']}", "record_view", {"rid": r.id})
    items.sort(key=lambda i: (i["date"], i["org"].lower(), i["name"].lower()))
    return items


def item_path(it):
    """Link that switches to the item's organisation first, then opens the item."""
    return url_for("org_view", org_id=it["org_id"], next=url_for(it["endpoint"], **it["args"]))


def _when(it):
    d = it["days"]
    if it["kind"] == "Password rotation":
        return (f"change overdue by {-d} day(s)" if d < 0 else "change due today" if d == 0
                else f"change due in {d} day(s)")
    if d < 0:
        return f"expired {-d} day(s) ago"
    if d == 0:
        return "expires today"
    return f"expires in {d} day(s)"


def build_digest(due, base_url):
    overdue = [i for i, _ in due if i["days"] < 0]
    lines = [f"{len(due)} item(s) need attention" + (f", {len(overdue)} already expired." if overdue else "."), ""]
    for title, pred in (("EXPIRED", lambda i: i["days"] < 0), ("EXPIRING SOON", lambda i: i["days"] >= 0)):
        group = [i for i, _ in due if pred(i)]
        if not group:
            continue
        lines.append(title)
        for i in group:
            lines.append(f"  * {i['org']} | {i['kind']}: {i['name']} - {_when(i)} ({i['date']:%d %b %Y})")
            if base_url:
                lines.append(f"      {base_url}{item_path(i)}")
        lines.append("")
    lines.append("You are receiving this because expiry alerts are enabled in CoreSight Vault (Admin > Expiry alerts).")
    return "\n".join(lines)


def run_alerts(force=False, base_url=""):
    """
    Check for items entering an alert window and email one digest.
    Normal runs only report an item once per threshold (and again after it is renewed);
    force=True ignores that history and sends everything currently inside a window (used for testing).
    """
    C = _CTX
    base_url = (base_url or os.environ.get("APP_BASE_URL") or "").rstrip("/")
    with C.app.test_request_context(base_url=(base_url or "http://localhost") + "/"):
        st = get_settings()
        if not force and not st.enabled:
            return {"sent": 0, "message": "Expiry alerts are switched off."}
        rcpts = parse_recipients(st.recipients)
        if not rcpts:
            return {"sent": 0, "message": "No recipients are configured."}
        thresholds = parse_days(st.days)
        due = []
        for it in collect_expiring():
            d = it["days"]
            if d < 0:
                t = 0
            else:
                c = [x for x in thresholds if d <= x]
                if not c:
                    continue
                t = min(c)
            if not force and C.AlertSent.query.filter_by(item_key=it["key"], threshold=t).first():
                continue
            due.append((it, t))

        now = datetime.utcnow()
        if not due:
            st.last_run_at, st.last_run_summary = now, "Checked: nothing new to report."
            C.db.session.commit()
            return {"sent": 0, "message": "Checked: nothing new to report."}

        overdue_n = sum(1 for i, _ in due if i["days"] < 0)
        subject = f"[CoreSight Vault] {len(due)} expiring item(s)" + (f", {overdue_n} expired" if overdue_n else "")
        body = build_digest(due, base_url)
        ok, errors = 0, []
        for r in rcpts:
            try:
                C.send_email(r, subject, body)
                ok += 1
            except Exception as e:  # SMTP not configured, refused, etc.
                errors.append(f"{r}: {e}")
        if ok and not force:
            for it, t in due:
                if not C.AlertSent.query.filter_by(item_key=it["key"], threshold=t).first():
                    C.db.session.add(C.AlertSent(item_key=it["key"], threshold=t))
        msg = f"Sent {len(due)} item(s) to {ok} recipient(s)." + (f" Failed: {'; '.join(errors)}" if errors else "")
        st.last_run_at, st.last_run_summary = now, msg[:300]
        C.db.session.commit()
        return {"sent": ok, "message": msg, "errors": errors}


# ---------------------------------------------------------------------------- init
def init(ctx):
    global _CTX
    _CTX = ctx
    app, db = ctx.app, ctx.db
    login_required = ctx.login_required
    AuditLog, User, Organization = ctx.AuditLog, ctx.User, ctx.Organization
    log_audit = ctx.log_audit

    # ---- "Expiring soon" badge (sidebar + home page)
    # Recomputed at most once a minute per worker, and immediately after any database commit in this worker.
    _summary_cache = {"at": None, "val": None}

    @event.listens_for(db.session, "after_commit")
    def _clear_summary(_session):
        _summary_cache["at"] = None

    @app.template_global()
    def expiry_summary():
        now = datetime.utcnow()
        if _summary_cache["at"] and (now - _summary_cache["at"]).total_seconds() < 60:
            return _summary_cache["val"]
        try:
            items = [i for i in collect_expiring() if i["days"] <= SOON_DAYS]
        except Exception:
            ctx.app.logger.exception("expiry summary failed")
            return {"expired": 0, "soon": 0, "total": 0, "by_org": {}}
        by_org = {}
        for i in items:
            by_org[i["org_id"]] = by_org.get(i["org_id"], 0) + 1
        val = {"expired": sum(1 for i in items if i["days"] < 0),
               "soon": sum(1 for i in items if i["days"] >= 0),
               "total": len(items), "by_org": by_org}
        _summary_cache.update(at=now, val=val)
        return val

    # ---- expiring page
    @app.route("/expiring")
    @login_required
    def expiring():
        window = request.args.get("window", 90, type=int)
        mine = request.args.get("scope") == "org"
        org = ctx.active_org()
        items = collect_expiring(org_id=org.id if (mine and org) else None)
        items = [i for i in items if i["days"] <= window]
        for i in items:
            i["url"] = item_path(i)
        counts = {"expired": sum(1 for i in items if i["days"] < 0),
                  "soon": sum(1 for i in items if 0 <= i["days"] <= SOON_DAYS)}
        return render_template("expiring.html", items=items, window=window, mine=mine, counts=counts, org=org)

    # ---- alert settings
    @app.route("/admin/alerts", methods=["GET", "POST"])
    @login_required
    def admin_alerts():
        ctx.super_admin_only()
        st = get_settings()
        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "save":
                days = parse_days(request.form.get("days"))
                if not days:
                    flash("Enter at least one number of days, e.g. 60, 30, 14, 7, 1.", "warning")
                else:
                    st.enabled = request.form.get("enabled") == "1"
                    st.recipients = ", ".join(parse_recipients(request.form.get("recipients")))
                    st.days = ",".join(str(d) for d in sorted(days, reverse=True))
                    db.session.commit()
                    log_audit("update", "alert_settings", st.id, details="Updated expiry alert settings")
                    flash("Alert settings saved.", "success")
            else:
                res = run_alerts(force=(action == "test"), base_url=request.host_url)
                flash(res["message"], "success" if res.get("sent") and not res.get("errors") else "info")
                log_audit("run", "alerts", st.id, details=f"{'Test digest' if action == 'test' else 'Manual check'}: {res['message']}")
            return redirect(url_for("admin_alerts"))
        smtp = ctx.get_smtp_settings()
        return render_template("admin_alerts.html", st=st, smtp_ok=bool(smtp.host and smtp.from_email),
                               preview=len([i for i in collect_expiring() if i["days"] <= (max(parse_days(st.days) or [0]))]))

    # ---- audit log viewer
    def _audit_query():
        q = AuditLog.query
        a = request.args
        if a.get("org", type=int):
            q = q.filter(AuditLog.org_id == a.get("org", type=int))
        if a.get("user", type=int):
            q = q.filter(AuditLog.user_id == a.get("user", type=int))
        if a.get("action"):
            q = q.filter(AuditLog.action == a.get("action"))
        if a.get("q"):
            like = f"%{a.get('q').strip()}%"
            q = q.filter(db.or_(AuditLog.details.ilike(like), AuditLog.entity_type.ilike(like)))
        for key, op in (("from", ">="), ("to", "<")):
            v = (a.get(key) or "").strip()
            if v:
                try:
                    d = datetime.strptime(v, "%Y-%m-%d")
                    if key == "to":
                        d = d + timedelta(days=1)
                    q = q.filter(AuditLog.created_at >= d) if key == "from" else q.filter(AuditLog.created_at < d)
                except ValueError:
                    pass
        return q.order_by(AuditLog.id.desc())

    def _csv_safe(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    @app.route("/admin/audit")
    @login_required
    def admin_audit():
        ctx.super_admin_only()
        q = _audit_query()
        users = {u.id: u.email for u in User.query.all()}
        orgs = {o.id: o.name for o in Organization.query.order_by(Organization.name).all()}

        if request.args.get("format") == "csv":
            rows = q.limit(50000).all()
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["time_utc", "user", "organisation", "action", "entity", "entity_id", "details"])
            for r in rows:
                w.writerow([r.created_at.strftime("%Y-%m-%d %H:%M:%S"), _csv_safe(users.get(r.user_id, "")),
                            _csv_safe(orgs.get(r.org_id, "")), _csv_safe(r.action), _csv_safe(r.entity_type),
                            _csv_safe(r.entity_id), _csv_safe(r.details)])
            log_audit("export", "audit_log", None, details=f"Exported {len(rows)} audit rows to CSV")
            return Response(buf.getvalue(), mimetype="text/csv",
                            headers={"Content-Disposition": f"attachment; filename=audit-log-{datetime.utcnow():%Y%m%d}.csv"})

        per = 50
        page = max(1, request.args.get("page", 1, type=int))
        total = q.count()
        rows = q.offset((page - 1) * per).limit(per).all()
        actions = [r[0] for r in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]
        args = {k: v for k, v in request.args.items() if k not in ("page", "format") and v}
        return render_template("admin_audit.html", rows=rows, users=users, orgs=orgs, actions=actions, args=args,
                               page=page, pages=max(1, -(-total // per)), total=total)

    # ---- backups
    def _db_path():
        url = db.engine.url
        if url.get_backend_name() != "sqlite" or not url.database:
            return None
        return Path(url.database)

    def _backup_dir():
        return Path(os.environ.get("BACKUP_DIR") or (ctx.BASE_DIR / "backups"))

    def _key_material():
        return app.config.get("VAULT_KEY") or app.config.get("SECRET_KEY") or ""

    @app.route("/admin/backups", methods=["GET", "POST"])
    @login_required
    def admin_backups():
        ctx.super_admin_only()
        bdir = _backup_dir()
        dbp = _db_path()
        if request.method == "POST":
            if dbp is None:
                flash("Backups currently support SQLite databases only.", "danger")
                return redirect(url_for("admin_backups"))
            unenc = request.form.get("unencrypted") == "1"
            pw = None
            if not unenc:
                pw = request.form.get("passphrase") or os.environ.get("BACKUP_PASSPHRASE")
                if request.form.get("passphrase"):
                    if len(pw) < 10:
                        flash("Use a passphrase of at least 10 characters.", "warning")
                        return redirect(url_for("admin_backups"))
                    if pw != request.form.get("passphrase2"):
                        flash("The two passphrases don't match.", "warning")
                        return redirect(url_for("admin_backups"))
                if not pw:
                    flash("Enter a passphrase (or tick 'unencrypted'). You'll need it to restore.", "warning")
                    return redirect(url_for("admin_backups"))
            try:
                out = backup_lib.create_backup(dbp, ctx.UPLOAD_ROOT, bdir, pw, _key_material())
                removed = backup_lib.prune(bdir, int(os.environ.get("BACKUP_KEEP", 14)))
                log_audit("backup", "system", None, details=f"Created backup {out.name} ({'encrypted' if pw else 'UNENCRYPTED'})")
                flash(f"Backup created: {out.name}" + (f" (removed {len(removed)} old backup(s))" if removed else ""), "success")
            except Exception as e:
                app.logger.exception("Backup failed")
                flash(f"Backup failed: {e}", "danger")
            return redirect(url_for("admin_backups"))
        return render_template("admin_backups.html", backups=backup_lib.list_backups(bdir), bdir=str(bdir),
                               sqlite_ok=dbp is not None, env_pass=bool(os.environ.get("BACKUP_PASSPHRASE")),
                               keep=int(os.environ.get("BACKUP_KEEP", 14)))

    def _safe_backup(name):
        if not backup_lib.NAME_RE.match(name or ""):
            abort(404)
        p = _backup_dir() / name
        if not p.is_file():
            abort(404)
        return p

    @app.route("/admin/backups/<name>/download")
    @login_required
    def admin_backup_download(name):
        ctx.super_admin_only()
        p = _safe_backup(name)
        log_audit("download", "system", None, details=f"Downloaded backup {p.name}")
        return send_file(p, as_attachment=True, download_name=p.name)

    @app.route("/admin/backups/<name>/delete", methods=["POST"])
    @login_required
    def admin_backup_delete(name):
        ctx.super_admin_only()
        p = _safe_backup(name)
        p.unlink()
        log_audit("delete", "system", None, details=f"Deleted backup {p.name}")
        flash("Backup deleted.", "success")
        return redirect(url_for("admin_backups"))
