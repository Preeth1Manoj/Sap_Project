from flask import current_app
from app import db
from app.models import User, Qualification

def ensure_admin_user():
    with current_app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin:
            admin.role = 'admin'
            admin.set_password('admin123')
            db.session.commit()
            print("Admin user password and role updated.")
        else:
            qualification = Qualification.query.first()
            if not qualification:
                qualification = Qualification(qualification='Admin Qualification')
                db.session.add(qualification)
                db.session.commit()
                print("Qualification created for admin user.")
            
            admin = User(
                username='admin',
                email='admin@example.com',
                first_name='Admin',
                last_name='User',
                role='admin',
                qualification_id=qualification.qualification_id
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully.")
        
        admin = User.query.filter_by(username='admin').first()
        is_correct = admin.check_password('admin123')
        print(f"Password verification for 'admin123': {is_correct}")