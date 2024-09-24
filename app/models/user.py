from app import db
from flask_login import UserMixin
import hashlib

class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(15))
    age = db.Column(db.Integer)
    passout_year = db.Column(db.Integer)
    qualification_id = db.Column(db.Integer, db.ForeignKey('qualification.qualification_id'))
    address = db.Column(db.String(255))
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()

    def get_id(self):
        return str(self.user_id)