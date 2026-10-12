"""
Custom record types, the records built from them, and links between any two records.

Registered from app.py with records.init(ctx); ctx is a snapshot of app.py's namespace
(app, db, models, helpers) so this module never imports app.py itself.
"""
import json
import re
from datetime import datetime, date

from flask import render_template, request, redirect, url_for, flash, jsonify, abort
from markupsafe import Markup
from sqlalchemy import event

FIELD_TYPES = [
    ("text", "Text"), ("textarea", "Long text"), ("url", "URL"), ("number", "Number"),
    ("date", "Date"), ("select", "Dropdown"), ("checkbox", "Yes / No"), ("password", "Password (encrypted)"),
]
FIELD_TYPE_KEYS = {k for k, _ in FIELD_TYPES}
MAX_FIELDS = 40

# One-click starting points shown when creating a new type.
PRESETS = {
    "Software licence": {
        "name": "Licence", "plural": "Licences", "description": "Software and subscription licences",
        "fields": [
            {"label": "Vendor", "type": "text"},
            {"label": "Licence key", "type": "password"},
            {"label": "Seats", "type": "number"},
            {"label": "Renewal date", "type": "date", "alert": True},
            {"label": "Portal URL", "type": "url"},
            {"label": "Notes", "type": "textarea"},
        ]},
    "Backup job": {
        "name": "Backup job", "plural": "Backup jobs", "description": "What is backed up, where and how",
        "fields": [
            {"label": "Product", "type": "text"},
            {"label": "Schedule", "type": "text"},
            {"label": "Retention", "type": "text"},
            {"label": "Destination", "type": "text"},
            {"label": "Last restore test", "type": "date"},
            {"label": "Notes", "type": "textarea"},
        ]},
    "VPN / remote access": {
        "name": "VPN", "plural": "VPNs", "description": "Remote access and tunnels",
        "fields": [
            {"label": "Type", "type": "select", "options": ["Site-to-site", "Client", "RDP gateway", "Other"]},
            {"label": "Endpoint", "type": "text"},
            {"label": "Pre-shared key", "type": "password"},
            {"label": "Certificate expires", "type": "date", "alert": True},
            {"label": "Notes", "type": "textarea"},
        ]},
}


def slugify(label):
    return re.sub(r"[^a-z0-9]+", "_", (label or "").lower()).strip("_")[:40] or "field"


def init(ctx):
    app, db = ctx.app, ctx.db
    CustomType, CustomRecord, RecordLink = ctx.CustomType, ctx.CustomRecord, ctx.RecordLink
    login_required, current_user = ctx.login_required, ctx.current_user
    log_audit = ctx.log_audit

    def admin_only():
        ctx.super_admin_only()

    # ------------------------------------------------------------------ entity registry
    def kinds():
        return {
            "password": ("Password", ctx.Password, lambda r: r.name, lambda r: url_for("pw_view", pw_id=r.id)),
            "asset": ("Asset", ctx.Asset, lambda r: r.device_name, lambda r: url_for("asset_view", asset_id=r.id)),
            "domain": ("Domain", ctx.Domain, lambda r: r.domain_name, lambda r: url_for("domain_view", domain_id=r.id)),
            "contact": ("Contact", ctx.SiteContact, lambda r: f"{r.first_name} {r.last_name}".strip(),
                        lambda r: url_for("contact_view", contact_id=r.id)),
            "site": ("Site", ctx.SiteAddress, lambda r: r.site_name, lambda r: url_for("site_view", site_id=r.id)),
            "doc": ("Document", ctx.DocPage, lambda r: r.title, lambda r: url_for("docs_page_view", page_id=r.id)),
            "record": ("Record", CustomRecord, lambda r: r.name, lambda r: url_for("record_view", rid=r.id)),
        }

    def get_entity(kind, eid, org_id):
        k = kinds().get(kind)
        if not k:
            return None
        obj = db.session.get(k[1], eid)
        return obj if obj is not None and getattr(obj, "org_id", None) == org_id else None

    def describe(kind, obj):
        label, _model, namef, urlf = kinds()[kind]
        if kind == "record" and obj.ctype is not None:
            label = obj.ctype.name
        return {"kind": kind, "kind_label": label, "name": namef(obj) or "(unnamed)", "url": urlf(obj)}

    def links_for(kind, eid, org_id):
        rows = RecordLink.query.filter(
            RecordLink.org_id == org_id,
            db.or_(db.and_(RecordLink.a_type == kind, RecordLink.a_id == eid),
                   db.and_(RecordLink.b_type == kind, RecordLink.b_id == eid))).all()
        items = []
        for ln in rows:
            ok, oid = (ln.b_type, ln.b_id) if (ln.a_type == kind and ln.a_id == eid) else (ln.a_type, ln.a_id)
            obj = get_entity(ok, oid, org_id)
            if obj is None:
                continue
            d = describe(ok, obj)
            d["link_id"] = ln.id
            items.append(d)
        items.sort(key=lambda d: (d["kind_label"].lower(), d["name"].lower()))
        return items

    ctx_links_for = links_for  # exported for the playbook builder
    ctx.links_for = ctx_links_for
    ctx.describe_entity = describe
    ctx.get_entity = get_entity

    # keep links tidy when a linked record is deleted
    def _cleanup(kind):
        def handler(mapper, connection, target):
            t = RecordLink.__table__
            connection.execute(t.delete().where(db.or_(
                db.and_(t.c.a_type == kind, t.c.a_id == target.id),
                db.and_(t.c.b_type == kind, t.c.b_id == target.id))))
        return handler

    for kind, spec in kinds().items():
        event.listen(spec[1], "after_delete", _cleanup(kind))

    # ------------------------------------------------------------------ "Related items" card
    @app.template_global()
    def related_card(kind, entity_id):
        org = ctx.active_org()
        if not org:
            return ""
        kind_options = [("password", "Passwords"), ("asset", "Assets"), ("domain", "Domains"), ("contact", "Contacts"),
                        ("site", "Sites"), ("doc", "Documents")]
        kind_options += [(f"record:{t.id}", t.label_plural) for t in CustomType.query.order_by(CustomType.name).all()]
        return Markup(render_template("_related.html", kind=kind, entity_id=entity_id,
                                      items=links_for(kind, entity_id, org.id), kind_options=kind_options))

    def parse_ref(ref):
        kind, _, rest = (ref or "").partition(":")
        try:
            return kind, int(rest)
        except ValueError:
            return None, None

    @app.route("/links/search")
    @login_required
    def links_search():
        org = ctx.active_org()
        if not org:
            return jsonify([])
        q = (request.args.get("q") or "").strip()
        kind = request.args.get("kind") or ""
        exclude = request.args.get("exclude") or ""
        like = f"%{q}%"
        out = []
        if kind.startswith("record:"):
            try:
                tid = int(kind.split(":", 1)[1])
            except ValueError:
                return jsonify([])
            rows = CustomRecord.query.filter(CustomRecord.org_id == org.id, CustomRecord.type_id == tid,
                                             CustomRecord.name.ilike(like)).order_by(CustomRecord.name).limit(15).all()
            out = [(r.id, r.name, "record") for r in rows]
        else:
            specs = {
                "password": (ctx.Password, ctx.Password.name), "asset": (ctx.Asset, ctx.Asset.device_name),
                "domain": (ctx.Domain, ctx.Domain.domain_name), "site": (ctx.SiteAddress, ctx.SiteAddress.site_name),
                "doc": (ctx.DocPage, ctx.DocPage.title),
            }
            if kind in specs:
                model, col = specs[kind]
                rows = model.query.filter(model.org_id == org.id, col.ilike(like)).order_by(col).limit(15).all()
                out = [(r.id, kinds()[kind][2](r), kind) for r in rows]
            elif kind == "contact":
                C = ctx.SiteContact
                rows = C.query.filter(C.org_id == org.id, db.or_(C.first_name.ilike(like), C.last_name.ilike(like),
                                                                  C.email.ilike(like))).limit(15).all()
                out = [(r.id, kinds()["contact"][2](r), "contact") for r in rows]
        return jsonify([{"ref": f"{k}:{i}", "name": n} for i, n, k in out if f"{k}:{i}" != exclude])

    @app.route("/links/add", methods=["POST"])
    @login_required
    def links_add():
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        a_kind, a_id = request.form.get("a_type"), request.form.get("a_id", type=int)
        b_kind, b_id = parse_ref(request.form.get("b"))
        back = request.referrer or url_for("orgs")
        if not (b_kind and a_id and b_id) or (a_kind, a_id) == (b_kind, b_id):
            flash("Pick an item to link to.", "warning")
            return redirect(back)
        if get_entity(a_kind, a_id, org.id) is None or get_entity(b_kind, b_id, org.id) is None:
            flash("Those items must belong to the current organisation.", "danger")
            return redirect(back)
        first, second = sorted([(a_kind, a_id), (b_kind, b_id)])
        exists = RecordLink.query.filter_by(a_type=first[0], a_id=first[1], b_type=second[0], b_id=second[1]).first()
        if not exists:
            db.session.add(RecordLink(org_id=org.id, a_type=first[0], a_id=first[1], b_type=second[0], b_id=second[1],
                                      created_by=current_user.id))
            db.session.commit()
            log_audit("link", a_kind, a_id, org_id=org.id, details=f"Linked {a_kind}:{a_id} with {b_kind}:{b_id}")
            flash("Linked.", "success")
        return redirect(back)

    @app.route("/links/<int:link_id>/delete", methods=["POST"])
    @login_required
    def links_delete(link_id):
        org = ctx.require_active_org()
        ln = db.session.get(RecordLink, link_id)
        if org and ln and ln.org_id == org.id:
            db.session.delete(ln)
            db.session.commit()
            log_audit("unlink", ln.a_type, ln.a_id, org_id=org.id,
                      details=f"Unlinked {ln.a_type}:{ln.a_id} from {ln.b_type}:{ln.b_id}")
            flash("Link removed.", "success")
        return redirect(request.referrer or url_for("orgs"))

    # ------------------------------------------------------------------ admin: record types
    def parse_fields(form, existing_keys=()):
        keys, labels, types = form.getlist("f_key"), form.getlist("f_label"), form.getlist("f_type")
        options, reqs, alerts = form.getlist("f_options"), form.getlist("f_required"), form.getlist("f_alert")
        fields, used, errors = [], set(), []
        for i, label in enumerate(labels):
            label = (label or "").strip()
            if not label:
                continue
            t = types[i] if i < len(types) and types[i] in FIELD_TYPE_KEYS else "text"
            key = (keys[i] if i < len(keys) else "").strip() or slugify(label)
            base, n = key, 2
            while key in used:
                key, n = f"{base}_{n}", n + 1
            used.add(key)
            f = {"key": key, "label": label[:80], "type": t, "required": (reqs[i] if i < len(reqs) else "0") == "1"}
            if t == "select":
                opts = [o.strip() for o in re.split(r"[,\n]", options[i] if i < len(options) else "") if o.strip()]
                if not opts:
                    errors.append(f'"{label}" is a dropdown but has no options.')
                f["options"] = opts[:50]
            if t == "date":
                f["alert"] = (alerts[i] if i < len(alerts) else "0") == "1"
            fields.append(f)
        if len(fields) > MAX_FIELDS:
            errors.append(f"A type can have at most {MAX_FIELDS} fields.")
        return fields, errors

    @app.route("/admin/types")
    @login_required
    def admin_types():
        admin_only()
        types = CustomType.query.order_by(CustomType.name).all()
        counts = {t.id: CustomRecord.query.filter_by(type_id=t.id).count() for t in types}
        return render_template("admin_types.html", types=types, counts=counts)

    def _save_type(t):
        name = (request.form.get("name") or "").strip()
        fields, errors = parse_fields(request.form)
        if not name:
            errors.append("Name is required.")
        dup = CustomType.query.filter(db.func.lower(CustomType.name) == name.lower(), CustomType.id != (t.id or 0)).first()
        if dup:
            errors.append("A type with that name already exists.")
        return name, fields, errors

    @app.route("/admin/types/new", methods=["GET", "POST"])
    @login_required
    def admin_type_new():
        admin_only()
        if request.method == "POST":
            t = CustomType()
            name, fields, errors = _save_type(t)
            if errors:
                for e in errors:
                    flash(e, "warning")
                draft = {"name": name, "plural": request.form.get("plural"), "description": request.form.get("description"),
                         "fields": fields}
                return render_template("admin_type_edit.html", t=None, draft=draft, field_types=FIELD_TYPES, presets=PRESETS)
            t.name, t.plural = name, (request.form.get("plural") or "").strip() or None
            t.description = (request.form.get("description") or "").strip() or None
            import json
            t.fields_json = json.dumps(fields)
            db.session.add(t)
            db.session.commit()
            log_audit("create", "record_type", t.id, details=f"Created record type: {t.name}")
            flash("Record type created.", "success")
            return redirect(url_for("admin_types"))
        return render_template("admin_type_edit.html", t=None, draft=None, field_types=FIELD_TYPES, presets=PRESETS)

    @app.route("/admin/types/<int:type_id>/edit", methods=["GET", "POST"])
    @login_required
    def admin_type_edit(type_id):
        admin_only()
        t = db.session.get(CustomType, type_id) or abort(404)
        if request.method == "POST":
            name, fields, errors = _save_type(t)
            if errors:
                for e in errors:
                    flash(e, "warning")
                draft = {"name": name, "plural": request.form.get("plural"), "description": request.form.get("description"),
                         "fields": fields}
                return render_template("admin_type_edit.html", t=t, draft=draft, field_types=FIELD_TYPES, presets=PRESETS)
            import json
            t.name, t.plural = name, (request.form.get("plural") or "").strip() or None
            t.description = (request.form.get("description") or "").strip() or None
            t.fields_json = json.dumps(fields)
            db.session.commit()
            log_audit("update", "record_type", t.id, details=f"Updated record type: {t.name}")
            flash("Record type saved. Existing records keep their data; removed fields are hidden but not erased.", "success")
            return redirect(url_for("admin_types"))
        return render_template("admin_type_edit.html", t=t, draft=None, field_types=FIELD_TYPES, presets=PRESETS)

    @app.route("/admin/types/<int:type_id>/delete", methods=["POST"])
    @login_required
    def admin_type_delete(type_id):
        admin_only()
        t = db.session.get(CustomType, type_id) or abort(404)
        recs = CustomRecord.query.filter_by(type_id=t.id).all()
        if recs and request.form.get("confirm") != "yes":
            flash(f"{len(recs)} record(s) use this type. Tick the confirmation box to delete them too.", "danger")
            return redirect(url_for("admin_types"))
        for r in recs:
            db.session.delete(r)
        db.session.delete(t)
        db.session.commit()
        log_audit("delete", "record_type", type_id, details=f"Deleted record type '{t.name}' and {len(recs)} record(s)")
        flash("Record type deleted.", "success")
        return redirect(url_for("admin_types"))

    # ------------------------------------------------------------------ records
    def collect(ctype, form, existing=None):
        import json  # noqa: F401
        data, errors = {}, []
        for f in ctype.fields:
            k, t = f["key"], f["type"]
            raw = (form.get("f_" + k) or "").strip()
            if t == "checkbox":
                data[k] = "1" if form.get("f_" + k) == "1" else ""
                continue
            if t == "password":
                if raw:
                    data[k] = ctx.encrypt_secret(raw)
                elif existing and existing.get(k) and form.get("clear_" + k) != "1":
                    data[k] = existing[k]
                else:
                    data[k] = ""
            else:
                if raw and t == "number":
                    try:
                        float(raw)
                    except ValueError:
                        errors.append(f'"{f["label"]}" must be a number.')
                if raw and t == "date":
                    try:
                        datetime.strptime(raw, "%Y-%m-%d")
                    except ValueError:
                        errors.append(f'"{f["label"]}" must be a valid date.')
                if raw and t == "select" and raw not in f.get("options", []):
                    errors.append(f'"{f["label"]}" has an invalid choice.')
                if raw and t == "url" and not re.match(r"^https?://", raw, re.I):
                    raw = "https://" + raw
                data[k] = raw[:20000]
            if f.get("required") and not data.get(k):
                errors.append(f'"{f["label"]}" is required.')
        return data, errors

    def type_or_404(type_id):
        return db.session.get(CustomType, type_id) or abort(404)

    def rec_for_org(rid, org):
        r = db.session.get(CustomRecord, rid)
        if not r or r.org_id != org.id:
            return None
        return r

    @app.route("/records/<int:type_id>")
    @login_required
    def records_list(type_id):
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        t = type_or_404(type_id)
        q = (request.args.get("q") or "").strip()
        qry = CustomRecord.query.filter_by(org_id=org.id, type_id=t.id)
        if q:
            qry = qry.filter(db.or_(CustomRecord.name.ilike(f"%{q}%"), CustomRecord.data_json.ilike(f"%{q}%")))
        rows = qry.order_by(CustomRecord.name).all()
        cols = [f for f in t.fields if f["type"] not in ("password", "textarea")][:3]
        return render_template("records_list.html", org=org, t=t, rows=rows, cols=cols, q=q)

    @app.route("/records/<int:type_id>/new", methods=["GET", "POST"])
    @login_required
    def record_new(type_id):
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        t = type_or_404(type_id)
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            data, errors = collect(t, request.form)
            if not name:
                errors.insert(0, "Name is required.")
            if errors:
                for e in errors:
                    flash(e, "warning")
                return render_template("record_form.html", org=org, t=t, rec=None, name=name,
                                       values={k: v for k, v in request.form.items()})
            import json
            r = CustomRecord(org_id=org.id, type_id=t.id, name=name[:200], data_json=json.dumps(data),
                             updated_by=current_user.id)
            db.session.add(r)
            db.session.commit()
            log_audit("create", "record", r.id, org_id=org.id, details=f"Created {t.name}: {r.name}")
            flash(f"{t.name} added.", "success")
            return redirect(url_for("record_view", rid=r.id))
        return render_template("record_form.html", org=org, t=t, rec=None, name="", values={})

    @app.route("/record/<int:rid>")
    @login_required
    def record_view(rid):
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        r = rec_for_org(rid, org)
        if not r:
            flash("Record not found in this organisation.", "danger")
            return redirect(url_for("orgs"))
        today = date.today()
        rows = []
        data = r.data
        for f in r.ctype.fields:
            v = data.get(f["key"], "")
            days = None
            if f["type"] == "date" and v and f.get("alert"):
                try:
                    days = (datetime.strptime(v, "%Y-%m-%d").date() - today).days
                except ValueError:
                    pass
            rows.append({"f": f, "value": v, "has_value": bool(v), "days": days})
        return render_template("record_view.html", org=org, r=r, t=r.ctype, rows=rows)

    @app.route("/record/<int:rid>/edit", methods=["GET", "POST"])
    @login_required
    def record_edit(rid):
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        r = rec_for_org(rid, org)
        if not r:
            flash("Record not found in this organisation.", "danger")
            return redirect(url_for("orgs"))
        t = r.ctype
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            data, errors = collect(t, request.form, existing=r.data)
            if not name:
                errors.insert(0, "Name is required.")
            if errors:
                for e in errors:
                    flash(e, "warning")
                return render_template("record_form.html", org=org, t=t, rec=r, name=name,
                                       values={k: v for k, v in request.form.items()})
            import json
            merged = r.data
            merged.update(data)           # fields removed from the type keep their stored data
            r.name, r.data_json, r.updated_by = name[:200], json.dumps(merged), current_user.id
            db.session.commit()
            log_audit("update", "record", r.id, org_id=org.id, details=f"Updated {t.name}: {r.name}")
            flash("Saved.", "success")
            return redirect(url_for("record_view", rid=r.id))
        values = {("f_" + k): v for k, v in r.data.items()}
        for f in t.fields:
            if f["type"] == "password":
                values.pop("f_" + f["key"], None)
        return render_template("record_form.html", org=org, t=t, rec=r, name=r.name, values=values)

    @app.route("/record/<int:rid>/delete", methods=["POST"])
    @login_required
    def record_delete(rid):
        org = ctx.require_active_org()
        if not org:
            return redirect(url_for("orgs"))
        r = rec_for_org(rid, org)
        if r:
            tid, name, tname = r.type_id, r.name, r.ctype.name
            db.session.delete(r)
            db.session.commit()
            log_audit("delete", "record", rid, org_id=org.id, details=f"Deleted {tname}: {name}")
            flash("Deleted.", "success")
            return redirect(url_for("records_list", type_id=tid))
        return redirect(url_for("orgs"))

    @app.route("/record/<int:rid>/secret/<key>")
    @login_required
    def record_secret(rid, key):
        org = ctx.active_org()
        r = rec_for_org(rid, org) if org else None
        field = next((f for f in (r.ctype.fields if r else []) if f["key"] == key and f["type"] == "password"), None)
        if not field:
            return jsonify({"error": "not found"}), 404
        log_audit("reveal", "record", r.id, org_id=org.id, details=f"Revealed '{field['label']}' on {r.ctype.name}: {r.name}")
        resp = jsonify({"value": ctx.decrypt_secret(r.data.get(key, "")) or ""})
        resp.headers["Cache-Control"] = "no-store"
        return resp
