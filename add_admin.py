"""
Create (or reset) a super-admin account.

    python add_admin.py                          # prompts for email + password
    python add_admin.py you@example.com          # prompts for password

A fresh install already seeds admin@local / admin (you must change the password
at first login), so you only need this to add more admins or recover access.
"""
import getpass
import sys

from app import app, db, User, password_meets_policy

email = (sys.argv[1] if len(sys.argv) > 1 else input("Email: ")).strip().lower()
pw = getpass.getpass("Temporary password: ")
if not password_meets_policy(pw):
    sys.exit("Password does not meet the complexity policy (length, upper/lower case, number, symbol).")

with app.app_context():
    u = User.query.filter_by(email=email).first()
    action = "Reset" if u else "Created"
    if not u:
        u = User(email=email)
        db.session.add(u)
    u.set_password(pw)
    u.role = "admin"
    u.is_admin = True
    u.is_super_admin = True
    u.is_active_user = True
    u.must_change_password = True
    u.failed_logins = 0
    u.locked_until = None
    db.session.commit()
    print(f"{action} super admin {email}. They must change the password at first login.")
