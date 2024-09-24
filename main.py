from flask import Flask, redirect, url_for, render_template, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField,HiddenField, IntegerField,SelectField, SubmitField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, NumberRange, Email,EqualTo, Length,ValidationError
from datetime import datetime,timedelta
from flask_bootstrap import Bootstrap
from flask_material import Material
from flask import send_file
from sqlalchemy import LargeBinary
from flask_migrate import Migrate
import base64
import hashlib 
from crud import Enquiry
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, IntegerField, TextAreaField, SubmitField
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy import desc
from flask import send_file
from io import BytesIO


app = Flask(__name__)
material = Material(app)
bootstrap = Bootstrap(app)

# Configuration
app.config.from_object('config.Config')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

current_time = datetime.utcnow()
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''

app.jinja_env.filters['b64encode'] = b64encode_filter

#Models
class Qualification(db.Model):
    qualification_id = db.Column(db.Integer, primary_key=True)
    qualification = db.Column(db.String(100), nullable=False)

class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash= db.Column(db.String(64), nullable=False)  
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(15))
    age = db.Column(db.Integer)
    passout_year = db.Column(db.Integer)
    qualification_id = db.Column(db.Integer, db.ForeignKey('qualification.qualification_id'))
    qualification = db.relationship('Qualification', backref='users')
    address = db.Column(db.String(255))
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()
    def get_id(self):
        return str(self.user_id)

class Course(db.Model):
    course_id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_image = db.Column(LargeBinary)  # For storing image data
    course_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    duration = db.Column(db.String(50))
    fees = db.Column(db.Float)
    qualification_id = db.Column(db.Integer, db.ForeignKey('qualification.qualification_id'))
    qualification = db.relationship('Qualification', backref='courses')
    modules = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)   
current_year = datetime.utcnow().year
from sqlalchemy import Column, Integer

class Enquiry(db.Model):
    enquiry_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.course_id'), nullable=False)
    enquiry_text = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    enquiry_status = db.Column(db.Integer, db.ForeignKey('enquiry_status.enquiry_status_id'), nullable=False)
    user = db.relationship('User', backref='enquiries')
    course = db.relationship('Course', backref='enquiries')
    status = db.relationship('EnquiryStatus', backref='enquiries')

class EnquiryStatus(db.Model):
    enquiry_status_id = db.Column(db.Integer, primary_key=True)
    enquiry_status = db.Column(db.String(100), nullable=False)

    enquiry = db.relationship('Enquiry', backref='enquiry_Status')

class Contactus(db.Model):
    contact_id = Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(10))
    email = db.Column(db.String(100), nullable=False)
    
#Flask Forms
class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired()])
    passout_year = SelectField('Passout Year', validators=[DataRequired()], coerce=int)
    qualification_id = SelectField('Qualification', validators=[DataRequired()], coerce=int)
    address = StringField('Address', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        current_year = datetime.utcnow().year
        self.passout_year.choices = [(year, str(year)) for year in range(current_year - 50, current_year + 10)]
        self.qualification_id.choices = [(q.qualification_id, q.qualification) for q in Qualification.query.all()]

class EditProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone No', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired()])
    passout_year = StringField('Year of Passout', validators=[DataRequired()])
    address = TextAreaField('Address')
    submit = SubmitField('Save')

class CourseForm(FlaskForm):
    course_code = StringField('Course Code', validators=[DataRequired()])
    course_image = FileField('Course Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    course_name = StringField('Course Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    duration = StringField('Duration')
    fees = FloatField('Fees')
    qualification_id = SelectField('Qualification', coerce=int, validators=[DataRequired()])
    modules = IntegerField('Number of Modules')
    submit = SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        super(CourseForm, self).__init__(*args, **kwargs)
        self.qualification_id.choices = [(q.qualification_id, q.qualification) for q in Qualification.query.all()]

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EnquirenowForm(FlaskForm):
    email = StringField('Email:',render_kw={"placeholder": "Enter your email"})
    course = SelectField('Course:',coerce=int,render_kw={"placeholder": "Select Course"})

    enquiry_text = StringField('Enquiry Message:',render_kw={"placeholder": "Enter your message"})
    submit_btn = SubmitField('Submit')
    
class Enquire_nowForm(FlaskForm):
    email = StringField('Email:',render_kw={"placeholder": "Enter your email"})
    course_id = HiddenField('Course ID')  
    course = StringField('Course Name:', render_kw={"placeholder": "Course Name","readonly": True})
    course_code = StringField('Course Code:', render_kw={"placeholder": "Course Code","readonly": True}) 
    enquiry_text = StringField('Enquiry Message:',render_kw={"placeholder": "Enter your message"})
    submit_btn = SubmitField('Submit')
    
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Enter your username"})
    first_name = StringField('First Name:', validators=[DataRequired()], render_kw={"placeholder": "Enter your first name"})
    last_name = StringField('Last Name:', validators=[DataRequired()], render_kw={"placeholder": "Enter your last name"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "Enter your email"})
    password = PasswordField('Password:', validators=[DataRequired(), Length(min=6)], render_kw={"placeholder": "Enter your password"})
    confirm_password = PasswordField('Confirm Password:', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm your password"})
    phone = StringField('Phone number:', validators=[DataRequired()], render_kw={"placeholder": "Enter your phone number"})
    age = IntegerField('Age:', validators=[DataRequired()], render_kw={"placeholder": "Enter your age"})
    passout_year = IntegerField('Passout year:', validators=[DataRequired()], render_kw={"placeholder": "Enter your passout year"})
    qualification_id = SelectField('Qualification', coerce=int, render_kw={"placeholder": "Select your qualification"})
    address = StringField('Address', validators=[DataRequired()], render_kw={"placeholder": "Enter your address"})
    submit = SubmitField('Register')
    
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')
    
#  authentication
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(f"Login attempt for user: {form.username.data}")
        if user:
            print(f"User found: {user.username}, Role: {user.role}")
            if user.check_password(form.password.data):
                login_user(user)
                print(f"Password check passed for user: {user.username}")
                flash('Login successful.', 'success')
                if user.role == 'admin':
                    print(f"Redirecting to admin_dashboard")
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('userdashboard'))
            else:
                print(f"Invalid password for user: {user.username}")
                flash('Invalid password', 'error')
        else:
            print(f"User not found: {form.username.data}")
            flash('Invalid username', 'error')
    return render_template('adminlogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/debug/db')
def debug_db():
    try:
        result = db.session.execute(db.text("SELECT 1")).scalar()
        return f"Database connection successful. Result: {result}"
    except Exception as e:
        return f"Database connection failed: {str(e)}"

@app.route('/debug/admin')
def debug_admin():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        return f"Admin user: {admin.username}, Role: {admin.role}, ID: {admin.user_id}, Password Hash: {admin.password_hash}"
    else:
        return "Admin user not found"



def ensure_admin_user():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin:
            # Ensure the role is set to 'admin'
            admin.role = 'admin'
            admin.set_password('admin123')
            db.session.commit()
            print("Admin user password and role updated.")
        else:
            # Check if a Qualification exists; if not, create one
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
        
        # Verifying the admin user's password
        admin = User.query.filter_by(username='admin').first()
        is_correct = admin.check_password('admin123')
        print(f"Password verification for 'admin123': {is_correct}")  
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    # Populate the qualification choices
    form.qualification_id.choices = [(q.qualification_id, q.qualification) for q in Qualification.query.all()]
    
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone=form.phone.data,
            age=form.age.data,
            passout_year=form.passout_year.data,
            qualification_id=form.qualification_id.data,
            address=form.address.data,
            role='user'  # Set a default role, or add a role field to the form if needed
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully', 'success')
        return redirect(url_for('login'))

    return render_template('register_user.html', form=form)

# Routes
@app.route('/')
def home():
    db.create_all()
    recent_courses = Course.query.order_by(Course.course_id.desc()).limit(3).all()
    return render_template('Main_Homepage.html',recent_courses=recent_courses)

#ADMIN Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    

    # Fetch counts
    user_count = User.query.count()
    course_count = Course.query.count()
   
    # pending_enquiries = Enquiry.query.filter_by(Enquiry_status='Pending').count()
    pending_enquiries = Enquiry.query.count()
    total_enquiries = Enquiry.query.count()

    # Calculate percentages
    target_users = 20
    target_courses = 20
    target_enquiries = 20
    user_percentage = min((user_count / target_users) * 100 if target_users > 0 else 0, 100)
    course_percentage = min((course_count / target_courses) * 100 if target_courses > 0 else 0, 100)
    enquiry_percentage = min((pending_enquiries / target_enquiries) * 100 if total_enquiries > 0 else 0, 100)

    # Fetch recent activities
    recent_user = User.query.order_by(desc(User.created_at)).first()
    recent_course = Course.query.order_by(desc(Course.course_id)).first()
    recent_enquiry = Enquiry.query.order_by(desc(Enquiry.created_at)).first()

    # Debug information
    print(f"Total users: {user_count}")
    print(f"Total courses: {course_count}")
    print(f"Pending enquiries: {pending_enquiries}")
    print(f"Total enquiries: {total_enquiries}")

    print(f"Recent user: {recent_user}")
    print(f"Recent course: {recent_course}")
    print(f"Recent enquiry: {recent_enquiry}")

    # Calculate time ago
    now = datetime.utcnow()
    user_time_ago = get_time_ago(recent_user.created_at, now) if recent_user else None
    course_time_ago = get_time_ago(recent_course.created_at, now) if recent_course else None
    enquiry_time_ago = get_time_ago(recent_enquiry.created_at, now) if recent_enquiry else None

    print(f"User time ago: {user_time_ago}")
    print(f"Course time ago: {course_time_ago}")
    print(f"Enquiry time ago: {enquiry_time_ago}")

    # If course_time_ago is None, try to debug why
    if course_time_ago is None and recent_course:
        print(f"Recent course created_at: {recent_course.created_at}")
        print(f"Current time: {now}")
        print(f"Time difference: {now - recent_course.created_at}")
    

    return render_template('admin1.html',
                           user_count=user_count,
                           course_count=course_count,
                           pending_enquiries=pending_enquiries,
                           user_percentage=round(user_percentage, 2),
                           course_percentage=round(course_percentage, 2),
                           enquiry_percentage=round(enquiry_percentage, 2),
                           recent_user=recent_user,
                           recent_course=recent_course,
                           recent_enquiry=recent_enquiry,
                           user_time_ago=user_time_ago,
                           course_time_ago=course_time_ago,
                           enquiry_time_ago=enquiry_time_ago)

def get_time_ago(past_time, now):
    if not past_time:
        return None
    diff = now - past_time
    if diff < timedelta(minutes=1):
        return 'just now'
    elif diff < timedelta(hours=1):
        return f'{diff.seconds // 60} minutes ago'
    elif diff < timedelta(days=1):
        return f'{diff.seconds // 3600} hours ago'
    else:
        return f'{diff.days} days ago'
    
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile(): 
    return render_template('profile.html')

#ADMIN USER CRUD OPERATIONS
@app.route('/users')
@login_required
def list_users():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('home'))
    users = User.query.filter(User.username != 'admin').all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('You do not have permission to add users.', 'error')
        return redirect(url_for('home'))
    form = UserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone=form.phone.data,
            age=form.age.data,
            passout_year=form.passout_year.data,
            qualification_id=form.qualification_id.data,
            address=form.address.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User added successfully', 'success')
        return redirect(url_for('list_users'))
   
    return render_template('adduser.html', form=form)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit users.', 'error')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(id)
    form = UserForm(obj=user)
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.phone = form.phone.data
        user.age = form.age.data
        user.passout_year = form.passout_year.data
        user.qualification_id = form.qualification_id.data
        user.address = form.address.data
        user.role = form.role.data       
        if form.password.data:
            user.set_password(form.password.data)        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('list_users'))
    form.password.data = user.password_hash
    form.confirm_password.data = user.password_hash 
    
    return render_template('edituser.html', form=form, user=user)

@app.route('/users/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete users.', 'error')
        return redirect(url_for('home'))
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('list_users'))


#ADMIN COURSE CRUD OPERATIONS

@app.route('/courses')
def list_courses():
    page = request.args.get('page', 1, type=int)
    courses = Course.query.order_by(Course.course_name).paginate(page=page, per_page=10, error_out=False)
    return render_template('course.html', courses=courses)

@app.route('/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role != 'admin':
        flash('You do not have permission to add courses.', 'error')
        return redirect(url_for('home'))
    form = CourseForm()
    if form.validate_on_submit():
        course = Course(
            course_code=form.course_code.data,
            course_name=form.course_name.data,
            description=form.description.data,
            duration=form.duration.data,
            fees=form.fees.data,
            qualification_id=form.qualification_id.data,
            modules=form.modules.data
        )
        if form.course_image.data:
            image_data = form.course_image.data.read()
            course.course_image = image_data
        db.session.add(course)
        db.session.commit()
        flash('Course added successfully', 'success')
        return redirect(url_for('list_courses'))
    return render_template('addcourse.html', form=form)

@app.route('/courses/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_course(id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit courses.', 'error')
        return redirect(url_for('home'))
    course = Course.query.get_or_404(id)
    form = CourseForm(obj=course)
    if form.validate_on_submit():
        form.populate_obj(course)
        if form.course_image.data:
            image_data = form.course_image.data.read()
            course.course_image = image_data
        db.session.commit()
        flash('Course updated successfully', 'success')
        return redirect(url_for('list_courses'))
    return render_template('editcourse.html', form=form, course=course)

@app.route('/courses/delete/<int:id>', methods=['POST'])
@login_required
def delete_course(id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete courses.', 'error')
        return redirect(url_for('home'))
    course = Course.query.get_or_404(id)
    db.session.delete(course)
    db.session.commit()
    flash('Course deleted successfully', 'success')
    return redirect(url_for('list_courses'))

@app.route('/course_image/<int:course_id>')
def course_image(course_id):
    course = Course.query.get_or_404(course_id)
    return send_file(BytesIO(course.course_image), mimetype='image/jpeg')


#ADMIN ENQUIRY CRUD OPERATIONS
@app.route('/admin/enquiries')
@login_required
def admin_enquiries():
    enquiries = Enquiry.query.options(db.joinedload(Enquiry.user), db.joinedload(Enquiry.course)).all()
    return render_template('enquiry.html', enquiries=enquiries)

@app.route('/enquiries')
@login_required
def list_enquiries():
    if current_user.role != 'admin':
        flash('You do not have permission to view enquiries.', 'error')
        return redirect(url_for('home'))
    enquiries = Enquiry.query.order_by(desc(Enquiry.enquiry_id)).all()
    enquiry_statuses = EnquiryStatus.query.all()
    return render_template('enquiry.html', enquiries=enquiries, enquiry_statuses=enquiry_statuses)

@app.route('/update_enquiry_status/<int:enquiry_id>', methods=['POST'])
@login_required
def update_enquiry_status(enquiry_id):
    if current_user.role != 'admin':
        flash('You do not have permission to update enquiry status.', 'error')
        return redirect(url_for('home'))
    
    enquiry = Enquiry.query.get_or_404(enquiry_id)
    new_status = request.form['status']
    
    # Get the EnquiryStatus object for the new status
    status_obj = EnquiryStatus.query.filter_by(enquiry_status=new_status).first()
    
    if status_obj:
        enquiry.enquiry_status = status_obj.enquiry_status_id
        db.session.commit()
        flash('Enquiry status updated successfully', 'success')
    else:
        flash('Invalid status', 'error')
    
    return redirect(url_for('list_enquiries'))

@app.route('/update_enquiry_response/<int:enquiry_id>', methods=['POST'])
@login_required
def update_enquiry_response(enquiry_id):
    if current_user.role != 'admin':
        flash('You do not have permission to update enquiry response.', 'error')
        return redirect(url_for('home'))
    
    enquiry = Enquiry.query.get_or_404(enquiry_id)
    enquiry.response = request.form['response']
    db.session.commit()
    flash('Enquiry response updated successfully', 'success')
    return redirect(url_for('list_enquiries'))

@app.route('/admin/delete_enquiry/<int:enquiry_id>', methods=['POST'])
@login_required
def delete_enquiry(enquiry_id):
    enquiry = Enquiry.query.get_or_404(enquiry_id)
    db.session.delete(enquiry)
    db.session.commit()
    flash('Enquiry has been deleted.', 'success')
    return redirect(url_for('admin_enquiries'))

#admin contact us
@app.route('/admin/contact-us')
@login_required
def admin_contact_us():
    contacts = Contactus.query.order_by(desc(Contactus.contact_id)).all()
    return render_template('admin_contact_us.html', contacts=contacts)


#USER Routes
@app.route('/userdashboard')
@login_required
def userdashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    recent_courses = Course.query.order_by(Course.course_id.desc()).limit(3).all()
    subquery = (
        db.session.query(
        Enquiry.course_id,
        db.func.count(Enquiry.enquiry_id).label('enquiry_count')
    )
    .group_by(Enquiry.course_id)
    ).subquery()
    popular_courses = (
        db.session.query(Course, subquery.c.enquiry_count)
        .outerjoin(subquery, Course.course_id == subquery.c.course_id)
        .order_by(db.desc(subquery.c.enquiry_count))  
        .limit(3)
        .all()
    )


    return render_template('User_logedin_HP.html',all_courses=Course.query.all(),recent_courses=recent_courses,popular_courses=popular_courses)

@app.route('/course')
@login_required
def course():
    recent_courses = Course.query.order_by(Course.created_at.desc()).limit(3).all()
    print(recent_courses)
    subquery = (
        db.session.query(
        Enquiry.course_id,
        db.func.count(Enquiry.enquiry_id).label('enquiry_count')
    )
     .group_by(Enquiry.course_id)
    ).subquery()
    popular_courses = (
        db.session.query(Course, subquery.c.enquiry_count)
        .outerjoin(subquery, Course.course_id == subquery.c.course_id)
        .order_by(db.desc(subquery.c.enquiry_count)) 
        .limit(3)
        .all()
    )

    return render_template('user_courses.html', all_courses=Course.query.all(),recent_courses=recent_courses,popular_courses=popular_courses)

@app.route('/search', methods=['GET'])
def search():
    search_query = request.args.get('query')
    all_courses = Course.query.filter(Course.course_name.contains(search_query)).all()
    subquery = (
        db.session.query(
        Enquiry.course_id,
        db.func.count(Enquiry.enquiry_id).label('enquiry_count')
    )
     .group_by(Enquiry.course_id)
    ).subquery()
    popular_courses = (
        db.session.query(Course, subquery.c.enquiry_count)
        .outerjoin(subquery, Course.course_id == subquery.c.course_id)
        .order_by(db.desc(subquery.c.enquiry_count)) 
        .limit(3)
        .all()
    )

    recent_courses = Course.query.order_by(Course.created_at.desc()).limit(3).all()
    return render_template('search_course.html', all_courses=all_courses, recent_courses=recent_courses,popular_courses=popular_courses)

@app.route('/FAQ')
def faq():
    return render_template('FAQ.html')

#USER Dashboard Enquiry
@app.route('/enquire_now', methods=['GET', 'POST'])
@login_required
def enquire_now():
    form = Enquire_nowForm()
    if request.method == 'GET':
        course_id = request.args.get('course_id')
        course_name = request.args.get('course_name')
        course_code = request.args.get('course_code')
        form.course_id.data = course_id
        form.course.data = course_name
        form.course_code.data = course_code 

    courses = Course.query.all()
    form.course.choices = [(c.course_id, c.course_name) for c in courses]

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and courses:
            enquiry = Enquiry(
                user_id=user.user_id, 
                course_id=form.course_id.data,
                enquiry_text=form.enquiry_text.data
            )
            db.session.add(enquiry)
            db.session.commit()
            flash("Enquiry submitted Successfully!", "success")
            return redirect(url_for('course'))
        else:
            flash("Email already exists", "danger")

    return render_template('enquirecourse.html', form=form, courses=courses)

@app.route('/enquirenow', methods=['GET', 'POST'])
@login_required
def enquirenow():
    form = EnquirenowForm()
    courses = Course.query.all()
    form.course.choices = [(c.course_id, c.course_name) for c in courses]

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Find the selected course to get the course_code
            selected_course = Course.query.get(form.course.data)
            course_code = selected_course.course_code if selected_course else ''

            enquiry = Enquiry(
                user_id=user.user_id,
                course_id=form.course.data,
                enquiry_text=form.enquiry_text.data,
                enquiry_status=1 
            )
            db.session.add(enquiry)
            db.session.commit()
            flash("Enquiry submitted Successfully!", "success")
            return redirect(url_for('userdashboard'))
        else:
            flash("Email already exists", "danger")

    return render_template('enquire_now.html', form=form, courses=courses) 

@app.route('/viewenquiries')
@login_required
def user_enquiries():
     # Fetch enquiries for the current user
     enquiries = Enquiry.query.filter_by(user_id=current_user.user_id).order_by(Enquiry.created_at.desc()).all()
    
     return render_template('myenquirystatus.html', enquiries=enquiries)
@app.route('/myuserdashboard')
@login_required
def  myuserdashboard():
    return render_template('Userdreamdashboard.html')


@app.route('/editprofile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        age = request.form.get('age')
        passout_year = request.form.get('passout_year')
        address = request.form.get('address')

        # Update the current user object
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        current_user.phone = phone
        current_user.age = age
        current_user.passout_year = passout_year
        current_user.address = address       
        
        db.session.commit()
        
        flash("Profile updated successfully!", "danger")
        
        return redirect(url_for('myuserdashboard'))

    return render_template('Editprofileuserdashboard.html')

@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('login'))
    return render_template('changepassworduserdashboard.html', form=form)

@app.route('/viewenquiriesuser')
@login_required
def  viewenquiriesuser():
    enquiries = Enquiry.query.filter_by(user_id=current_user.user_id).order_by(Enquiry.created_at.desc()).all()
    return render_template('viewenquiryuserdashboard.html',enquiries=enquiries)

class ContactusForm(FlaskForm):
    name = StringField('Name:',render_kw={"placeholder": "Enter your name"})
    phone = StringField('Phone :',render_kw={"placeholder": "Enter your phone"})
    email = StringField('Email:',render_kw={"placeholder": "Enter your email"})
    submit_btn = SubmitField('Submit')
    
@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    form = ContactusForm()
    if form.validate_on_submit():
            contactus = Contactus(
                name = form.name.data,
                phone = form.phone.data,
                email = form.email.data,
            )
            db.session.add(contactus)
            db.session.commit()
            flash("Enquiry submitted Successfully!", "success")
            return redirect(url_for('userdashboard'))

    return render_template('contact_us.html', form=form) 

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'),404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_admin_user()
    app.run(debug=True)

