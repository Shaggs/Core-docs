rom app import app, db, User

with app.app_context():
    u = User(email="admin@local")
    u.set_password("TempPassword123!")
    u.is_super_admin = True
    u.must_change_password = True
    db.session.add(u)
    db.session.commit()
