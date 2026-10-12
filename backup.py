"""
Backup and restore for CoreSight Vault (SQLite installs).

A backup is one file containing a consistent snapshot of the database, every
uploaded file, and a small manifest. If you give it a passphrase the whole file is
encrypted (PBKDF2 + Fernet, in chunks, so large uploads don't need to fit in memory).

The vault encryption key (VAULT_KEY / SECRET_KEY in .env) is deliberately NOT inside
the backup, so a stolen backup can't be opened without it. Keep .env backed up
separately; the manifest stores a fingerprint so a restore can warn if it doesn't match.

Command line (run from the project folder):

    python backup.py create [--keep 14]      # uses BACKUP_PASSPHRASE from .env if set
    python backup.py list
    python backup.py restore FILE [--yes]    # stop the web app first
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CVBK1\n"
KDF_ITERATIONS = 600_000
CHUNK = 1024 * 1024
NAME_RE = re.compile(r"^coresightvault-backup-\d{8}-\d{6}\.(zip|cvbak)$")


class BackupError(Exception):
    pass


# ---------------------------------------------------------------- encryption
def _key(passphrase, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_file(src, dst, passphrase):
    salt = os.urandom(16)
    f = Fernet(_key(passphrase, salt, KDF_ITERATIONS))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(MAGIC + salt + struct.pack(">I", KDF_ITERATIONS))
        index = 0
        block = fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK)
            last = 1 if not nxt else 0
            token = f.encrypt(struct.pack(">QB", index, last) + block)
            fout.write(struct.pack(">I", len(token)) + token)
            if last:
                break
            index += 1
            block = nxt


def decrypt_file(src, dst, passphrase):
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        if fin.read(len(MAGIC)) != MAGIC:
            raise BackupError("This isn't an encrypted CoreSight Vault backup.")
        salt = fin.read(16)
        (iterations,) = struct.unpack(">I", fin.read(4))
        f = Fernet(_key(passphrase, salt, iterations))
        expected, seen_last = 0, False
        while True:
            hdr = fin.read(4)
            if not hdr:
                break
            if seen_last:
                raise BackupError("Backup file has unexpected extra data.")
            (n,) = struct.unpack(">I", hdr)
            token = fin.read(n)
            if len(token) != n:
                raise BackupError("Backup file is truncated.")
            try:
                plain = f.decrypt(token)
            except InvalidToken:
                raise BackupError("Wrong passphrase, or the backup file is damaged.")
            index, last = struct.unpack(">QB", plain[:9])
            if index != expected:
                raise BackupError("Backup chunks are out of order.")
            fout.write(plain[9:])
            expected += 1
            seen_last = bool(last)
        if not seen_last:
            raise BackupError("Backup file is truncated.")


def is_encrypted(path):
    with open(path, "rb") as f:
        return f.read(len(MAGIC)) == MAGIC


# ---------------------------------------------------------------- helpers
def key_fingerprint(key_material):
    return hashlib.sha256((key_material or "").encode()).hexdigest()[:12]


def list_backups(backup_dir):
    backup_dir = Path(backup_dir)
    if not backup_dir.is_dir():
        return []
    out = []
    for p in sorted(backup_dir.iterdir(), reverse=True):
        if NAME_RE.match(p.name):
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "created": datetime.fromtimestamp(st.st_mtime),
                        "encrypted": p.suffix == ".cvbak"})
    return out


def prune(backup_dir, keep):
    if not keep or keep < 1:
        return []
    old = list_backups(backup_dir)[keep:]
    for b in old:
        try:
            (Path(backup_dir) / b["name"]).unlink()
        except OSError:
            pass
    return [b["name"] for b in old]


# ---------------------------------------------------------------- create
def create_backup(db_path, uploads_dir, backup_dir, passphrase=None, key_material="", progress=None):
    """Returns the path of the new backup file."""
    db_path, uploads_dir, backup_dir = Path(db_path), Path(uploads_dir), Path(backup_dir)
    if not db_path.is_file():
        raise BackupError(f"Database file not found: {db_path}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    try:
        backup_dir.chmod(0o700)
    except OSError:
        pass

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    final = backup_dir / f"coresightvault-backup-{stamp}.{'cvbak' if passphrase else 'zip'}"

    with tempfile.TemporaryDirectory(dir=backup_dir) as tmp:
        tmp = Path(tmp)
        snap = tmp / "coresight.db"
        # SQLite's online backup API gives a consistent copy even while the app is running.
        src = sqlite3.connect(str(db_path))
        try:
            dst = sqlite3.connect(str(snap))
            with dst:
                src.backup(dst)
            dst.close()
        finally:
            src.close()

        zpath = tmp / "payload.zip"
        count = 0
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            z.write(snap, "coresight.db")
            if uploads_dir.is_dir():
                for f in sorted(uploads_dir.rglob("*")):
                    if f.is_file() and not f.is_symlink():
                        z.write(f, "uploads/" + f.relative_to(uploads_dir).as_posix())
                        count += 1
            z.writestr("manifest.json", json.dumps({
                "format": 1, "app": "CoreSight Vault", "created_at": datetime.utcnow().isoformat() + "Z",
                "db_file": "coresight.db", "uploads_files": count,
                "encrypted": bool(passphrase), "vault_key_fingerprint": key_fingerprint(key_material),
            }, indent=2))

        part = final.with_suffix(final.suffix + ".part")
        if passphrase:
            encrypt_file(zpath, part, passphrase)
        else:
            shutil.move(str(zpath), part)
        os.replace(part, final)
    try:
        final.chmod(0o600)
    except OSError:
        pass
    return final


# ---------------------------------------------------------------- restore
def read_manifest(path, passphrase=None):
    with tempfile.TemporaryDirectory() as tmp:
        zp = _open_payload(path, passphrase, tmp)
        with zipfile.ZipFile(zp) as z:
            return json.loads(z.read("manifest.json"))


def _open_payload(path, passphrase, tmp):
    path = Path(path)
    if is_encrypted(path):
        if not passphrase:
            raise BackupError("This backup is encrypted - a passphrase is required.")
        out = Path(tmp) / "payload.zip"
        decrypt_file(path, out, passphrase)
        return out
    return path


def restore_backup(path, db_path, uploads_dir, passphrase=None, key_material=""):
    """
    Replace the database and uploads with the contents of a backup. The current
    data is moved aside (…pre-restore-<timestamp>) rather than deleted.
    Returns (manifest, warnings).
    """
    db_path, uploads_dir = Path(db_path), Path(uploads_dir)
    warnings = []
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    with tempfile.TemporaryDirectory() as tmp:
        zp = _open_payload(path, passphrase, tmp)
        with zipfile.ZipFile(zp) as z:
            names = z.namelist()
            if "manifest.json" not in names or "coresight.db" not in names:
                raise BackupError("This doesn't look like a CoreSight Vault backup.")
            manifest = json.loads(z.read("manifest.json"))
            fp = manifest.get("vault_key_fingerprint")
            if fp and key_material is not None and fp != key_fingerprint(key_material):
                warnings.append("The VAULT_KEY/SECRET_KEY in your .env is different from the one this backup was "
                                "made with. Stored passwords will NOT decrypt until you restore the original .env.")
            # extract into a staging area first, so a bad archive can't half-restore
            stage = Path(tmp) / "stage"
            stage.mkdir()
            for n in names:
                if n == "manifest.json":
                    continue
                target = (stage / n).resolve()
                if not str(target).startswith(str(stage.resolve())):
                    raise BackupError("Backup contains an unsafe path.")
                z.extract(n, stage)
            # move current data aside, then swap in the restored data
            if db_path.exists():
                shutil.move(str(db_path), str(db_path) + f".pre-restore-{stamp}")
            for suffix in ("-wal", "-shm"):
                leftover = Path(str(db_path) + suffix)
                if leftover.exists():
                    leftover.unlink()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(stage / "coresight.db"), str(db_path))
            if uploads_dir.exists():
                shutil.move(str(uploads_dir), str(uploads_dir) + f".pre-restore-{stamp}")
            if (stage / "uploads").is_dir():
                shutil.move(str(stage / "uploads"), str(uploads_dir))
            else:
                uploads_dir.mkdir(parents=True, exist_ok=True)
    return manifest, warnings


# ---------------------------------------------------------------- CLI
def _paths_from_app():
    from app import app, db, UPLOAD_ROOT  # imported lazily: needs the app configured
    with app.app_context():
        url = db.engine.url
        if url.get_backend_name() != "sqlite" or not url.database:
            raise BackupError("Backups currently support SQLite databases only.")
        db_path = Path(url.database)
        key_material = app.config.get("VAULT_KEY") or app.config.get("SECRET_KEY") or ""
        db.engine.dispose()
    backup_dir = Path(os.environ.get("BACKUP_DIR") or (Path(__file__).resolve().parent / "backups"))
    return db_path, Path(UPLOAD_ROOT), backup_dir, key_material


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def main(argv=None):
    ap = argparse.ArgumentParser(description="CoreSight Vault backup / restore")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--keep", type=int, default=int(os.environ.get("BACKUP_KEEP", 14)), help="how many backups to keep (0 = all)")
    c.add_argument("--no-encrypt", action="store_true", help="write an unencrypted .zip")
    sub.add_parser("list")
    r = sub.add_parser("restore")
    r.add_argument("file")
    r.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    args = ap.parse_args(argv)

    try:
        db_path, uploads, backup_dir, key_material = _paths_from_app()
        if args.cmd == "list":
            for b in list_backups(backup_dir):
                print(f"{b['name']:50} {_human(b['size']):>9}  {b['created']:%Y-%m-%d %H:%M}  {'encrypted' if b['encrypted'] else 'UNENCRYPTED'}")
            return 0
        if args.cmd == "create":
            pw = None if args.no_encrypt else os.environ.get("BACKUP_PASSPHRASE")
            if not pw and not args.no_encrypt:
                print("BACKUP_PASSPHRASE is not set; writing an UNENCRYPTED backup. "
                      "Set it in .env to encrypt backups.", file=sys.stderr)
            out = create_backup(db_path, uploads, backup_dir, pw, key_material)
            removed = prune(backup_dir, args.keep)
            print(f"Backup written: {out} ({_human(out.stat().st_size)})" + (f"; removed {len(removed)} old" if removed else ""))
            return 0
        if args.cmd == "restore":
            f = Path(args.file)
            if not f.is_file():
                f = backup_dir / args.file
            if not f.is_file():
                raise BackupError(f"File not found: {args.file}")
            pw = None
            if is_encrypted(f):
                pw = os.environ.get("BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
            m = read_manifest(f, pw)
            print(f"Backup made {m.get('created_at')} with {m.get('uploads_files')} uploaded file(s).")
            print(f"This will REPLACE the database at {db_path} and the uploads at {uploads}.")
            print("Current data is moved aside (…pre-restore-<time>), not deleted. Stop the web app first.")
            if not args.yes and input("Type 'restore' to continue: ").strip() != "restore":
                print("Cancelled.")
                return 1
            manifest, warnings = restore_backup(f, db_path, uploads, pw, key_material)
            for w in warnings:
                print("WARNING:", w)
            print("Restore complete. Start the web app again.")
            return 0
    except BackupError as e:
        print("Error:", e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
