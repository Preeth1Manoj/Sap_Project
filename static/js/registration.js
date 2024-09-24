function myformvalfn(form) {
    let haserror = false;

    const errorIds = ['usernameerror', 'firstnameerror', 'lastnameerror', 'emailerror', 'phonenumbererror', 
                      'passworderror', 'cnfpassworderror', 'ageerror', 'passoutyearerror', 'qualificationerror', 'addresserror'];
    
    errorIds.forEach(id => {
        document.getElementById(id).textContent = "";
    });

    const formFields = ['username', 'first_name', 'last_name', 'email', 'phone', 'password', 'confirm_password', 
                        'age', 'passout_year', 'qualification_id', 'address'];
    
    formFields.forEach(field => {
        form[field].style.border = '1px solid black';
    });

    function checkField(fieldName, errorId, errorMessage) {
        const field = form[fieldName];
        const errorElement = document.getElementById(errorId);
        if (!field.value) {
            errorElement.textContent = errorMessage;
            field.style.border = '1px solid red';
            haserror = true;
        }
    }

    checkField('username', 'usernameerror', 'Enter Username');
    checkField('first_name', 'firstnameerror', 'Enter First name');
    checkField('last_name', 'lastnameerror', 'Enter Last name');
    checkField('email', 'emailerror', 'Enter Email');
    checkField('phone', 'phonenumbererror', 'Enter Phone number');
    checkField('password', 'passworderror', 'Enter Password');
    checkField('confirm_password', 'cnfpassworderror', 'Confirm Password');
    checkField('age', 'ageerror', 'Enter Age');
    checkField('passout_year', 'passoutyearerror', 'Enter Year of Passout');
    checkField('qualification_id', 'qualificationerror', 'Select Qualification');
    checkField('address', 'addresserror', 'Enter Address');

    if (form.phone.value && !/^\d{10}$/.test(form.phone.value)) {
        document.getElementById("phonenumbererror").textContent = "10 digits are required";
        form.phone.style.border = '1px solid red';
        haserror = true;
    }

    if (form.password.value !== form.confirm_password.value) {
        document.getElementById("cnfpassworderror").textContent = "Passwords do not match";
        form.confirm_password.style.border = '1px solid red';
        haserror = true;
    }

    if (form.age.value && (isNaN(form.age.value) || form.age.value < 1 || form.age.value > 120)) {
        document.getElementById("ageerror").textContent = "Enter a valid Age";
        form.age.style.border = '1px solid red';
        haserror = true;
    }

    if (form.passout_year.value && (isNaN(form.passout_year.value) || form.passout_year.value < 1900 || form.passout_year.value > 2099)) {
        document.getElementById("passoutyearerror").textContent = "Enter a valid Year of Passout";
        form.passout_year.style.border = '1px solid red';
        haserror = true;
    }

    return !haserror;
}

document.getElementById("resetButton").addEventListener("click", function() {
    const errorIds = ['usernameerror', 'firstnameerror', 'lastnameerror', 'emailerror', 'phonenumbererror', 
                      'passworderror', 'cnfpassworderror', 'ageerror', 'passoutyearerror', 'qualificationerror', 'addresserror'];
    
    errorIds.forEach(id => {
        document.getElementById(id).textContent = "";
    });

    const formFields = ['username', 'first_name', 'last_name', 'email', 'phone', 'password', 'confirm_password', 
                        'age', 'passout_year', 'qualification_id', 'address'];
    
    formFields.forEach(field => {
        document.getElementsByName(field)[0].style.border = '1px solid black';
    });
});