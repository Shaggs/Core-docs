"""
Rotate VAULT_KEY: re-encrypt every stored secret with a brand-new key.

    1. Stop the web app (and any cron jobs) first.
    2. python rotate_key.py            # shows what it will do, asks you to type ROTATE
    3. Start the web app again.

What it does, in order:
  * checks every encrypted value can be read with the CURRENT key (stops if any can't, nothing changed)
  * makes a backup of the database + uploads (encrypted with BACKUP_PASSPHRASE if set)
  * re-encrypts everything with a NEW key inside one database transaction and checks the result
  * also encrypts any password-vault fields that were still stored in plain text
  * saves the old .env as .env.before-rotation-<time> and writes the new key into .env

Keep the old .env copy until you've checked everything works: backups made before the rotation
can only be restored with the OLD key. Then store it offline or delete it.
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

# Columns that should always be encrypted (anything else is re-encrypted only if it already carries "enc:")
SECRET_COLUMNS = {("password", "username_plain"), ("password", "password_plain"), ("password", "otp_secret"),
                  ("password_history", "username_plain"), ("password_history", "password_plain"),
                  ("password_history", "otp_secret")}


def _walk_json(obj, fn):
    if isinstance(obj, dict):
        return {k: _walk_json(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_json(v, fn) for v in obj]
    if isinstance(obj, str) and obj.startswith("enc:"):
        return fn(obj)
    return obj


def plan_changes(conn, old, new):
    """Return (updates, stats, unreadable). updates = [(table, column, rowid, new_value)]."""
    from sqlalchemy import inspect, text
    insp = inspect(conn)
    updates, unreadable = [], []
    stats = {"reencrypted": 0, "plain_encrypted": 0}

    def swap(token):
        try:
            plain = old.decrypt(token[4:].encode()).decode()
        except Exception:
            raise ValueError("unreadable")
        stats["reencrypted"] += 1
        return "enc:" + new.encrypt(plain.encode()).decode()

    for table in insp.get_table_names():
        cols = [c["name"] for c in insp.get_columns(table)
                if str(c["type"]).upper().startswith(("VARCHAR", "TEXT", "CHAR", "STRING")) or str(c["type"]) == ""]
        for col in cols:
            rows = conn.execute(text(f'SELECT rowid, "{col}" FROM "{table}" WHERE "{col}" IS NOT NULL AND "{col}" != \'\'')).fetchall()
            for rowid, val in rows:
                if not isinstance(val, str):
                    continue
                try:
                    if val.startswith("enc:"):
                        updates.append((table, col, rowid, swap(val)))
                    elif '"enc:' in val and val.lstrip()[:1] in "{[":
                        try:
                            data = json.loads(val)
                        except ValueError:
                            continue
                        updates.append((table, col, rowid, json.dumps(_walk_json(data, swap))))
                    elif (table, col) in SECRET_COLUMNS:
                        updates.append((table, col, rowid, "enc:" + new.encrypt(val.encode()).decode()))
                        stats["plain_encrypted"] += 1
                except ValueError:
                    unreadable.append(f"{table}.{col} row {rowid}")
    return updates, stats, unreadable


def verify(conn, new, updates):
    from sqlalchemy import text
    for table, col, rowid, _ in updates:
        val = conn.execute(text(f'SELECT "{col}" FROM "{table}" WHERE rowid = :r'), {"r": rowid}).scalar()
        tokens = [val] if val.startswith("enc:") else []
        if not tokens:
            _walk_json(json.loads(val), lambda t: tokens.append(t) or t)
        for t in tokens:
            new.decrypt(t[4:].encode())   # raises if wrong


def write_env(env_path, new_key):
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    out, done = [], False
    for ln in lines:
        if ln.strip().startswith("VAULT_KEY="):
            out.append(f"VAULT_KEY={new_key}"); done = True
        else:
            out.append(ln)
    if not done:
        out.append(f"VAULT_KEY={new_key}")
    tmp = env_path.with_name(env_path.name + ".new")
    tmp.write_text("\n".join(out) + "\n")
    os.chmod(tmp, 0o600)
    return tmp


def main(argv=None):
    ap = argparse.ArgumentParser(description="Re-encrypt all stored secrets with a new VAULT_KEY.")
    ap.add_argument("--yes", action="store_true", help="don't ask for confirmation (for scripts)")
    ap.add_argument("--env-file", default=str(BASE / ".env"), help="path to .env (default: next to app.py)")
    ap.add_argument("--no-backup", action="store_true", help="skip the automatic backup (not recommended)")
    args = ap.parse_args(argv)

    from cryptography.fernet import Fernet
    import app as A
    import backup as backup_lib

    env_path = Path(args.env_file)
    old = A._get_vault_cipher()
    new_key = Fernet.generate_key().decode()
    new = Fernet(new_key.encode())

    with A.app.app_context():
        with A.db.engine.connect() as conn:
            updates, stats, unreadable = plan_changes(conn, old, new)
        if unreadable:
            print(f"STOPPED: {len(unreadable)} value(s) can't be decrypted with the current key, so nothing was changed.")
            for u in unreadable[:20]:
                print("   ", u)
            print("Check VAULT_KEY in .env is the key this data was saved with.")
            return 2
        print(f"{stats['reencrypted']} encrypted value(s) will be re-encrypted with a new key"
              + (f", and {stats['plain_encrypted']} plain-text password field(s) will be encrypted." if stats["plain_encrypted"] else "."))
        if not updates:
            print("Nothing is encrypted yet; a new key will simply be written to .env.")
        if not args.yes:
            print("\nStop the web app before continuing (a running app still holds the old key).")
            if input("Type ROTATE to continue: ").strip() != "ROTATE":
                print("Cancelled; nothing changed.")
                return 1

        if not args.no_backup:
            db_path, uploads, bdir, key_material = backup_lib._paths_from_app()
            res = backup_lib.create_backup(db_path, uploads, bdir, passphrase=os.environ.get("BACKUP_PASSPHRASE") or None,
                                           key_material=key_material)
            print("Backup saved:", res.get("path") if isinstance(res, dict) else res)

        tmp_env = write_env(env_path, new_key)
        try:
            from sqlalchemy import text
            with A.db.engine.begin() as conn:   # one transaction: all or nothing
                for table, col, rowid, val in updates:
                    conn.execute(text(f'UPDATE "{table}" SET "{col}" = :v WHERE rowid = :r'), {"v": val, "r": rowid})
                verify(conn, new, updates)
        except Exception as e:
            tmp_env.unlink(missing_ok=True)
            print(f"FAILED ({e}); the database was left unchanged and .env was not touched.")
            return 3

        if env_path.exists():
            keep = env_path.with_name(f"{env_path.name}.before-rotation-{datetime.now():%Y%m%d-%H%M%S}")
            shutil.copy2(env_path, keep)
            os.chmod(keep, 0o600)
            print("Old .env kept as", keep.name, "(needed to restore backups made before today; store it offline).")
        os.replace(tmp_env, env_path)
        try:
            with A.app.test_request_context():   # log_audit needs a request context in scripts
                A.log_audit("rotate", "vault_key", None,
                            details=f"VAULT_KEY rotated: {stats['reencrypted']} re-encrypted, "
                                    f"{stats['plain_encrypted']} plain values encrypted")
        except Exception:
            pass
    print("Done. Start the web app again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
