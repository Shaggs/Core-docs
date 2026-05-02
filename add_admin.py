from app import app, db, User

with app.app_context():
    u = User(email="admin@locals")
    u.set_password("Admin1234")
    u.is_super_admin = True
    u.must_change_password = False
    db.session.add(u)
    db.session.commit()
