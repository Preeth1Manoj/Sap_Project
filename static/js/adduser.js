function myformvalfn(form) {
    var firstname, lastname, email, phnumber, age, year, qual, address, user, pwd;

    let haserror = false;

    // Getting values from the textboxes
    firstname = form.txtfirstname.value;
    lastname = form.txtlastname.value;
    email = form.txtemail.value;
    phnumber = form.txtphnum.value;
    age = form.txtage.value;
    year = form.txtyear.value;
    qual = form.txtqual.value;
    address = form.txtaddress.value;
    user = form.txtuser.value;
    pwd = form.txtpwd.value;

    // Resetting styles and error messages
    form.txtfirstname.style.border = '1px solid black';
    form.txtlastname.style.border = '1px solid black';
    form.txtemail.style.border = '1px solid black';
    form.txtphnum.style.border = '1px solid black';
    form.txtage.style.border = '1px solid black';
    form.txtyear.style.border = '1px solid black';
    form.txtqual.style.border = '1px solid black';
    form.txtaddress.style.border = '1px solid black';
    form.txtuser.style.border = '1px solid black';
    form.txtpwd.style.border = '1px solid black';

    document.getElementById("firstnameerror").textContent = "";
    document.getElementById("lastnameerror").textContent = "";
    document.getElementById("emailerror").textContent = "";
    document.getElementById("phonenumbererror").textContent = "";
    document.getElementById("ageerror").textContent = "";
    document.getElementById("yearerror").textContent = "";
    document.getElementById("qualerror").textContent = "";
    document.getElementById("addresserror").textContent = "";
    document.getElementById("usererror").textContent = "";
    document.getElementById("passworderror").textContent = "";

    // Validations
    if (firstname.length === 0) {
        document.getElementById("firstnameerror").textContent = "Enter First name";
        haserror = true;
        form.txtfirstname.style.border = '1px solid red';
    }

    if (lastname.length === 0) {
        document.getElementById("lastnameerror").textContent = "Enter Last name";
        haserror = true;
        form.txtlastname.style.border = '1px solid red';
    }

    if (email.length === 0) {
        document.getElementById("emailerror").textContent = "Enter Email";
        haserror = true;
        form.txtemail.style.border = '1px solid red';
    } else if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
        document.getElementById("emailerror").textContent = "Invalid Email";
        haserror = true;
        form.txtemail.style.border = '1px solid red';
    }

    if (phnumber.length === 0) {
        document.getElementById("phonenumbererror").textContent = "Enter Phone number";
        haserror = true;
        form.txtphnum.style.border = '1px solid red';
    } else if (!/^\d{10}$/.test(phnumber)) {
        document.getElementById("phonenumbererror").textContent = "10 digits are required";
        haserror = true;
        form.txtphnum.style.border = '1px solid red';
    }

    if (age.length === 0) {
        document.getElementById("ageerror").textContent = "Enter Age";
        haserror = true;
        form.txtage.style.border = '1px solid red';
    }

    if (year.length === 0) {
        document.getElementById("yearerror").textContent = "Enter Year of Passout";
        haserror = true;
        form.txtyear.style.border = '1px solid red';
    }

    if (qual.length === 0) {
        document.getElementById("qualerror").textContent = "Enter Qualification";
        haserror = true;
        form.txtqual.style.border = '1px solid red';
    }

    if (address.length === 0) {
        document.getElementById("addresserror").textContent = "Enter Address";
        haserror = true;
        form.txtaddress.style.border = '1px solid red';
    }

    if (user.length === 0) {
        document.getElementById("usererror").textContent = "Enter Username";
        haserror = true;
        form.txtuser.style.border = '1px solid red';
    }

    if (pwd.length === 0) {
        document.getElementById("passworderror").textContent = "Enter Password";
        haserror = true;
        form.txtpwd.style.border = '1px solid red';
    }

    return !haserror;
}

// Event listener to reset error messages and field borders when the reset button is clicked
document.getElementById("resetButton").addEventListener("click", function() {

    // Clear error messages
    document.getElementById("firstnameerror").textContent = "";
    document.getElementById("lastnameerror").textContent = "";
    document.getElementById("emailerror").textContent = "";
    document.getElementById("ageerror").textContent = "";
    document.getElementById("qualerror").textContent = "";
    document.getElementById("yearerror").textContent = "";
    document.getElementById("phonenumbererror").textContent = "";
    document.getElementById("passworderror").textContent = "";
    document.getElementById("usererror").textContent = "";
    document.getElementById("addresserror").textContent = "";

    // Reset input field borders
    document.getElementById("txtfirstname").style.border = '1px solid black';
    document.getElementById("txtlastname").style.border = '1px solid black';
    document.getElementById("txtemail").style.border = '1px solid black';
    document.getElementById("txtphnum").style.border = '1px solid black';
    document.getElementById("txtage").style.border = '1px solid black';
    document.getElementById("txtqual").style.border = '1px solid black';
    document.getElementById("txtyear").style.border = '1px solid black';
    document.getElementById("txtaddress").style.border = '1px solid black';
    document.getElementById("txtpwd").style.border = '1px solid black';
    document.getElementById("txtuser").style.border = '1px solid black';
});