# HANDOFF: CoreSight Vault (Core-docs)

> **To the next Claude:** read this file first, then continue from section 6 ("What's left").
> Section 9 is a dated change log (what changed, file by file) if you need to know why something is the way it is.
> The owner is an MSP (IT managed-service provider) building an IT Glue / Hudu-style documentation vault.
> They are not a developer: explain choices in plain language, keep replies short, and run the tests before claiming anything works.

## 1. What this is
Flask + SQLAlchemy + SQLite app (Bootstrap 5.3, Quill editor). Clients are "organisations"; each has contacts, sites,
network devices, domains, assets, encrypted passwords, documentation (rich-text pages + uploads), onboarding checklist.
Repo: https://github.com/Shaggs/Core-docs  (the owner uploads the zip to GitHub; there is no git access from the sandbox).

## 2. Run it
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python init_env.py          # writes .env with random SECRET_KEY + VAULT_KEY (never change them after data exists)
python app.py               # http://localhost:5001   login admin@local / admin (forced password change)
python tests/test_features.py   # expect: 128 passed, 0 failed
# or: docker compose up -d --build   (see README → Docker)
```

## 3. Layout
| File | Purpose |
|---|---|
| `app.py` | Models, core routes (orgs, passwords, docs, assets, domains…), login/2FA, CSRF + role enforcement, schema migration |
| `records.py` | Custom record types, records, record links (`init(ctx)`) |
| `ops.py` | Expiry tracking + alert emails, audit log viewer, backups page (`init(ctx)`) |
| `backup.py` | Backup/restore engine + CLI (encrypted, chunked Fernet) |
| `playbook.py` | Client PDF export (ReportLab + pypdf), no Flask dependency |
| `send_alerts.py`, `add_admin.py`, `init_env.py` | CLI helpers |
| `rotate_key.py` | Re-encrypts all secrets with a new VAULT_KEY (backup first, all-or-nothing, keeps old .env copy) |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | Container + scheduler (alerts 07:00, backup 02:30, `TZ` in .env); data in `vault-data` volume at `/data` |
| `.github/workflows/tests.yml` | CI: runs the tests + `docker build` on every push/PR |
| `tests/test_features.py` | 128 end-to-end checks (Flask test client, scratch DB + scratch uploads dir) |
| `templates/` | Jinja templates (`_related.html`, `records_*`, `admin_*`, `expiring.html`, `org_export.html`…) |

**Pattern to know:** `records.py` and `ops.py` don't import `app.py` (it can run as `__main__`, which would create a second app).
At the bottom of `app.py`, `records.init(ns)` / `ops.init(ns)` receive a snapshot of app.py's globals (`ctx.db`, `ctx.Password`, …).
Any helper a module needs must be defined in `app.py` *before* that block.

## 4. Features built so far (all tested)
1. **One-time password share links**: expire (default 5 min), reveal once via POST (GET never consumes, so email scanners can't burn it), revoke, audit-logged, auto-hide after 5 min.
2. **Client playbook PDF**: cover, contents, all sections, custom records, related items, optional attachments, optional passwords (admin only, re-enter account password, PDF must be AES-256 encrypted, 12+ char password). Unicode needs DejaVu fonts (falls back + flags unprintable chars).
3. **CSRF**: Flask-WTF; an `after_request` hook injects the token into every POST form; a `fetch` wrapper in `base.html` adds `X-CSRFToken`; the public share page is exempt. `SameSite=Lax` cookies.
4. **Roles**: `admin` / `tech` / `readonly` (`User.role`, synced to legacy `is_admin`/`is_super_admin`). Read-only blocked from all non-GET requests in `enforce_roles()`. Can't demote/disable the last admin. Admin-only: users, SMTP, record types, alerts, audit, backups, password exports.
5. **Audit log viewer** `/admin/audit` (filters, pagination, CSV with formula-injection protection).
6. **Expiry tracking** `/expiring` + daily digest (`send_alerts.py`); sources: domains, asset warranty (new field), custom date fields with "alert" ticked. Dedup table `AlertSent`.
7. **Custom record types** `/admin/types` (presets: Software licence, Backup job, VPN) + records `/records/<type>`; password-type fields stored encrypted; in global search + playbook.
8. **Record links**: generic two-way links (`RecordLink`) between password/asset/domain/contact/site/doc/custom record, same org only; "Related items" card via `{{ related_card('kind', id) }}`; links auto-removed when a record is deleted (SQLAlchemy `after_delete`).
9. **Backups** `/admin/backups` + `backup.py`: SQLite online-backup snapshot + uploads + manifest, optional passphrase encryption, retention, restore CLI (moves current data aside), key-fingerprint mismatch warning. `.env` is intentionally NOT in the backup.
10. **Dark theme**: Bootstrap `data-bs-theme`, Auto/Light/Dark toggle, localStorage, plus overrides for `.bg-light`, `.table-light`, Quill.
11. Fixes along the way: broken forced-password-change, `.env` never loaded, open redirect on `?next=`, seeded admin forced to change password, `cryptography` missing from requirements (secrets were silently stored unencrypted).
12. Upgrade path verified: an old DB gains the new columns/tables automatically (`ensure_columns()`, `SCHEMA_ADDITIONS`).
13. **Visual review** of every page, dark + light + 390px phone width (Playwright). Fixed: invisible Admin/Revoked badges in dark, page overflowing sideways on phones (`.main-content{min-width:0}`), unstyled code blocks/quotes in saved docs, backup sizes, QR code background (CSS change only; the 2FA page was not re-screenshotted).
14. **Multi-worker startup fix**: `_startup()` in app.py takes a file lock so `gunicorn -w 2` on a fresh DB no longer crashes (UNIQUE constraint race). Verified with a clean venv + gunicorn + 17 live HTTP checks (`smoke_http.py`, not in repo).
15. **Read-only UI**: write buttons/forms wrapped in `{% if can_write %}`; asset-assignment and onboarding forms use `<fieldset disabled>`.
16. **Expiring badge**: `expiry_summary()` template global in ops.py (cached 60 s per worker, cleared on any commit); sidebar pill + home banner + per-client pill. `SOON_DAYS = 30`.
17. **Welcome/reset links**: new users get a one-time set-password link (72 h, salt `welcome-set-password`); admin-typed passwords are never emailed; link shown on screen if email fails. All reset links are single-use (token carries a fingerprint of the password hash).
18. **Key rotation** (`rotate_key.py`), also encrypts legacy plain-text password fields.
19. `UPLOAD_DIR` setting; tests no longer delete the real `uploads/` folder (they used to!).
20. Docker + compose + GitHub Actions. Legacy templates deleted.
21. **Password extras (owner asked for this, overriding the earlier postponement):** generator button (browser `crypto.getRandomValues`, unbiased, one of each character type); `Password.folder` / `tags` / `rotate_days` / `password_changed_at` (in `SCHEMA_ADDITIONS`, upgrade verified on an old DB); list grouped by folder with folder/tag/search filters; tags in global search + CSV import; rotation reminders feed `collect_expiring()` as "Password rotation" (badge, Expiring page, digest). The rotation clock restarts only when the password value itself changes (not on rollback).
22. **Bugs fixed while doing 21:** editing a password silently wiped its 2FA secret (blank box now = keep; "Remove OTP" tickbox works); every edit form printed empty values as the text "None" and saved it back (fixed app-wide with `app.jinja_env.finalize`). Existing data may already contain literal "None" values in URL/notes fields from before the fix.

## 5. Decisions the owner made (don't relitigate)
- MSP model: **no per-client permissions**; roles are global.
- Read-only users CAN view/reveal passwords (they need to read them); they cannot change, share or export.
- SQLite only for now; backups are SQLite-only.
- Integrations were deliberately postponed. (Password extras were postponed too, then the owner asked for them: done, see 21.)

## 6. What's left (in priority order)
1. **Sanitise document HTML (security, recommended).** `docs_page_new/edit` store `body_html` as submitted and `doc_page_view.html` renders it with `|safe`, so a tech account can store a `<script>` that runs with an admin's session. Fix: clean on save with an allow-list (e.g. `nh3`), keeping Quill's tags/classes. **The owner was asked twice and hasn't answered yet; ask once more, don't do it unasked.**
2. **Password URL links (same family as 1).** `pw_view.html` renders `<a href="{{ row.url }}">`, so a `javascript:` URL saved by a tech account would run when clicked. Fix: only link `http(s)://` URLs, show anything else as plain text. Small; suggest bundling with 1.
3. Optional one-off cleanup: turn literal "None" text (saved by the old form bug, see 4.22) back into empty values in URL/notes/etc. Ask the owner first; someone could genuinely have typed "None".
4. Integrations (RMM, Microsoft 365, PSA): **postponed by owner (section 5)**, ask before starting.
5. Not yet verified (no tooling in the sandbox): the Docker image build (first GitHub Actions run will build it; check the Actions log), the GitHub workflow itself, and `rotate_key.py` on real data (tell the owner to try it on a copy first).
6. Visual checks not done: 2FA QR page and login page after the CSS change; the new password list/form (item 4.21) only checked at desktop width, not phone width.
7. Nice-to-haves: "Resend welcome link" button on the users page; folder/tags in the playbook PDF password section.

## 7. Gotchas learned
- In a bash tool, `pkill -f "<pattern>"` can match its own command line and kill the shell. Use `ps aux | grep "[p]attern" | awk '{print $2}' | xargs kill`.
- Background servers die when the command ends unless started with `(nohup setsid ... &)`.
- `log_audit()` swallows errors outside a request: in scripts wrap in `app.test_request_context()`.
- `create_all()` doesn't add columns: add to `SCHEMA_ADDITIONS` in `app.py` for any new column on an existing table.
- Never edit CSRF per-form: the injector handles `<form method="post">`; JS-created fetches must use `fetch()` (wrapped), not `XMLHttpRequest`.
- ReportLab Paragraph text is XML: always pass user text through `playbook.T()` / `TL()`. TOC entries need escaping too (already done).
- Flask-SQLAlchemy resolves *relative* sqlite URLs under `instance/`; the default DB path in `app.py` is absolute. Backups ask the engine for the real path.
- The password edit URL is `/passwords/<id>` (no `/edit`); grep-based checks for "/edit" miss it.
- New write buttons in templates must be wrapped in `{% if can_write %}`; the read-only test scans pages for write URLs.
- Any startup DB work must stay inside `_startup()` (it holds the cross-worker lock).
- Tests set `UPLOAD_DIR`/`BACKUP_DIR`/`DATABASE_URL` to a temp dir; keep it that way so they're safe on a live server.
- Jinja prints `None` as empty (`app.jinja_env.finalize`); don't rely on "None" appearing in templates.
- `send_email` is looked up at call time, so tests monkeypatch `A.send_email` to capture emails.
- `rotate_key.py` treats any text column value starting with `enc:` as an encrypted secret; if a user typed such text into e.g. notes, rotation stops (safely, nothing changed) and lists the row.
- Password rotation reminders use `password_changed_at`, falling back to `updated_at` for rows that pre-date the column.
- Visual checks: seed demo data, serve with werkzeug `make_server` in a thread, route `https://cdn.jsdelivr.net/**` to `npm install bootstrap@5.3.3 quill@1.3.7` copies, theme via `localStorage.setItem('theme', ...)` in an init script. Full-page screenshots make the fixed sidebar look short: that's a screenshot artefact, not a bug.

## 8. Prompt to paste into the new conversation
> I'm continuing a project from another Claude session. The attached zip is a Flask app called CoreSight Vault (an IT Glue/Hudu-style documentation tool for my MSP). Read `HANDOFF.md` in the zip first. Then: (1) run `python tests/test_features.py` and confirm it reports 128 passed, (2) complete the items in section 6 of HANDOFF.md in order, running the tests after each, and (3) give me a fresh zip I can upload to GitHub, with a short plain-English summary of what changed. Ask me before making any change that conflicts with section 5.

## 9. Change log

### 2026-10-11: session 2 (section 6 items 1–5, 7, 9, 10, then item 6 at the owner's request)
Tests went from 76 to 128 checks; all pass. A clean install under `gunicorn -w 2` passes 17 live HTTP checks.

**New files**
- `rotate_key.py`: VAULT_KEY rotation CLI (see 4.18).
- `Dockerfile`, `docker-compose.yml`, `.dockerignore`: container image (DejaVu fonts + tzdata, non-root user, healthcheck) and a `scheduler` service that runs `send_alerts.py` after 07:00 and `backup.py create` after 02:30 once per day.
- `.github/workflows/tests.yml`: runs the test suite and `docker build` on every push/PR.

**Deleted**
- `templates/base-2.html`, `templates/org_view-2.html`, `templates/domain_view.html.old.html` (unused).

**Changed: app.py**
- `_startup()` with a cross-worker file lock replaces the bare `create_all()/ensure_columns()/seed_defaults()` block.
- `UPLOAD_ROOT` honours the `UPLOAD_DIR` env var.
- Reset tokens: `generate_reset_token(user, welcome=False)` / `verify_reset_token(token) -> (user, is_welcome)`; payload carries a password-hash fingerprint, so links are single-use; welcome links use their own salt and last 72 h.
- `admin_users_new`: password optional (blank = emailed set-password link); typed passwords never emailed; link shown on screen if email fails.
- `reset_password` handles both link kinds, audit-logs, and shows a clearer policy message.
- Password model: `folder`, `tags`, `rotate_days`, `password_changed_at` + `tag_list` / `rotation_due_on` properties; four `SCHEMA_ADDITIONS` entries.
- Helpers `parse_tags`, `password_meta_from_form`, `pw_form_context`, `ROTATION_CHOICES`.
- `pw_list` (folder/tag/search filters, grouping), `pw_new`, `pw_edit` (rotation clock, **2FA secret no longer wiped**, clear-OTP works), `pw_import` (folder/tags columns), `pw_view` (passes `today`), global search includes folder/tags.
- `app.jinja_env.finalize` prints `None` as empty (fixes "None" being saved by every edit form).
- New imports: `hmac`.

**Changed: ops.py**
- `expiry_summary()` template global (60 s cache, cleared on commit) and `SOON_DAYS = 30`.
- `collect_expiring()` includes "Password rotation" items; `_when()` wording for them.

**Changed: templates**
- `base.html`: sidebar expiry badge; `.main-content{min-width:0}`; dark-mode Quill code/quote styling; `.doc-page-content` styles; `.tag-chip` / `.pw-table` styles; `.bg-white:not(img)`.
- Read-only: `{% if can_write %}` around write controls in `asset_view`, `assets_list`, `contact_view`, `contacts_list`, `domain_list`, `domain_view`, `network_list`, `orgs`, `pw_list`, `pw_view`, `site_view`, `sites_list`, `doc_page`, `doc_page_view`, `docs_list`, `org_view` (export button); `<fieldset disabled>` in `asset_view` (assignment) and `onboarding`.
- `orgs.html`: expiry banner + per-client pill. `expiring.html`: rotation wording.
- `admin_users.html` (Admin badge colour), `pw_view.html` (Revoked badge, read-only share note, folder/tags/rotation badges), `admin_backups.html` (`filesizeformat`).
- `admin_users_new.html` and `reset_password.html` rewritten for the link flow.
- `pw_edit.html`: folder, tags + suggestion chips, rotation dropdown, generator; empty fields no longer show "None".
- `pw_list.html` rewritten (search, folder/tag filters, grouped tables). `pw_import.html`: documents the new columns.

**Changed: other**
- `tests/test_features.py`: uses scratch `UPLOAD_DIR` and no longer deletes the real `uploads/`; new sections for read-only UI, expiry badge, welcome links, key rotation, folders/tags/rotation/2FA, "None" fields.
- `README.md`: features, Docker, key rotation, adding users, new settings, test count, roadmap.
- `.env.example`: `UPLOAD_DIR`, `TZ`.

**Bugs found and fixed this session (all pre-existing)**
1. `gunicorn -w 2` crashed on a fresh database (startup race).
2. The test script deleted the real `uploads/` folder.
3. Forgot-password links could be reused for an hour.
4. Editing a password wiped its 2FA secret.
5. Edit forms saved empty fields as the text "None".
6. Dark-mode Admin badge invisible; pages wider than a phone screen.

### Before 2026-10-11: session 1
Items 4.1–4.12 (share links, playbook PDF, CSRF, roles, audit viewer, expiry tracking, custom record types, record links, backups, dark theme, early fixes, upgrade path).

