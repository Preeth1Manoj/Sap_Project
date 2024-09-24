from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from app.models.course import Course
from app.forms.course import CourseForm
from app import db

bp = Blueprint('courses', __name__)

@bp.route('/courses')
def list_courses():
    page = request.args.get('page', 1, type=int)
    courses = Course.query.order_by(Course.course_name).paginate(page=page, per_page=10, error_out=False)
    return render_template('course.html', courses=courses)

@bp.route('/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    form = CourseForm()
    if form.validate_on_submit():
        course = Course(
            course_code=form.course_code.data,
            course_name=form.course_name.data,
            description=form.description.data,
            duration=form.duration.data,
            fees=form.fees.data,
            qualifications=form.qualifications.data,
            modules=form.modules.data
        )
        if form.course_image.data:
            image_data = form.course_image.data.read()
            course.course_image = image_data
        db.session.add(course)
        db.session.commit()
        flash('Course added successfully', 'success')
        return redirect(url_for('courses.list_courses'))
    return render_template('addcourse.html', form=form)

@bp.route('/courses/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_course(id):
    course = Course.query.get_or_404(id)
    form = CourseForm(obj=course)
    if form.validate_on_submit():
        form.populate_obj(course)
        if form.course_image.data:
            image_data = form.course_image.data.read()
            course.course_image = image_data
        db.session.commit()
        flash('Course updated successfully', 'success')
        return redirect(url_for('courses.list_courses'))
    return render_template('editcourse.html', form=form, course=course)

@bp.route('/courses/delete/<int:id>', methods=['POST'])
@login_required
def delete_course(id):
    course = Course.query.get_or_404(id)
    db.session.delete(course)
    db.session.commit()
    flash('Course deleted successfully', 'success')
    return redirect(url_for('courses.list_courses'))