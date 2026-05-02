from app import app, db, User

with app.app_context():
    u = User(email="shane@locals")
    u.set_password("Alarm1001")
    u.is_super_admin = True
    u.must_change_password = False
    db.session.add(u)
    db.session.commit()
