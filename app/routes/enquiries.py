from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.enquiry import Enquiry

bp = Blueprint('enquiries', __name__)

@bp.route('/enquiries')
@login_required
def list_enquiries():
    if current_user.role != 'admin':
        flash('You do not have permission to view enquiries.', 'error')
        return redirect(url_for('auth.login'))
    enquiries = Enquiry.query.all()
    return render_template('enquiries.html', enquiries=enquiries)