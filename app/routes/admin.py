from flask import Blueprint, render_template, flash
from flask_login import login_required, current_user
from app.models.user import User
from app.models.course import Course
from app.models.enquiry import Enquiry

bp = Blueprint('admin', __name__)

@bp.route('/admin')
@login_required
def dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('auth.login'))
    user_count = User.query.count()
    course_count = Course.query.count()
    pending_enquiries = Enquiry.query.filter_by(status='Pending').count()
    return render_template('admin1.html', user_count=user_count, course_count=course_count, pending_enquiries=pending_enquiries)

@bp.route('/users')
@login_required
def list_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('auth.login'))
    users = User.query.all()
    return render_template('users.html', users=users)