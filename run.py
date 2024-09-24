from app import create_app, db
from app.utils import ensure_admin_user

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_admin_user()
    app.run(debug=True)