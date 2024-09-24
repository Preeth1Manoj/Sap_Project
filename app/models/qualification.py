from app import db

class Qualification(db.Model):
    qualification_id = db.Column(db.Integer, primary_key=True)
    qualification = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Qualification {self.qualification}>'