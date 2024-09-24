from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FloatField, IntegerField, SubmitField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired

class CourseForm(FlaskForm):
    course_code = StringField('Course Code', validators=[DataRequired()])
    course_image = FileField('Course Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    course_name = StringField('Course Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    duration = StringField('Duration')
    fees = FloatField('Fees')
    qualifications = StringField('Qualifications')
    modules = IntegerField('Number of Modules')
    submit = SubmitField('Submit')