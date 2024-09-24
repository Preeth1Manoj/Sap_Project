// addcourse.js

function validateForm(form) {
    clearErrors();
    let isValid = true;

    if (form.course_code.value.trim() === "") {
        showError('course_code_error', 'Course Code is required.');
        isValid = false;
    }

    if (form.course_image.files.length === 0) {
        showError('course_image_error', 'Course Image is required.');
        isValid = false;
    }

    if (form.course_name.value.trim() === "") {
        showError('course_name_error', 'Course Name is required.');
        isValid = false;
    }

    if (form.description.value.trim() === "") {
        showError('description_error', 'Description is required.');
        isValid = false;
    }

    if (form.duration.value.trim() === "") {
        showError('duration_error', 'Duration is required.');
        isValid = false;
    }

    const fees = form.fees.value.trim();
    if (fees === "" || isNaN(fees)) {
        showError('fees_error', 'Fees must be a valid number.');
        isValid = false;
    }

    if (form.qualifications.value.trim() === "") {
        showError('qualifications_error', 'Qualifications are required.');
        isValid = false;
    }

    const modules = form.modules.value.trim();
    if (modules === "" || isNaN(modules)) {
        showError('modules_error', 'Course Modules must be a valid number.');
        isValid = false;
    }

    return isValid;
}

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
    }
}

function clearErrors() {
    const errorElements = document.querySelectorAll('small.text-danger');
    errorElements.forEach(element => {
        element.textContent = '';
    });
}

function resetForm() {
    document.getElementById('addCourseForm').reset();
    clearErrors();
}