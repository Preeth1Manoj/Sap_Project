from app import db
from sqlalchemy import LargeBinary

class Course(db.Model):
    course_id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_image = db.Column(LargeBinary)
    course_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    duration = db.Column(db.String(50))
    fees = db.Column(db.Float)
    qualifications = db.Column(db.String(200))
    modules = db.Column(db.Integer)