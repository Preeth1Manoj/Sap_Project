from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user
from app.models.user import User
from app.forms import LoginForm  # Updated import

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('adminlogin.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))