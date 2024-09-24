from app import db
from datetime import datetime

class Enquiry(db.Model):
    enquiry_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.course_id'), nullable=False)
    enquiry_text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)