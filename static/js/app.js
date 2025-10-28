

document.addEventListener("DOMContentLoaded", function () {

    // ✅ Function to handle password toggle
    function setupPasswordToggle(inputId, toggleId) {
        const input = document.getElementById(inputId);
        const toggle = document.getElementById(toggleId);

        if (!input || !toggle) return;

        toggle.addEventListener("click", function () {
            const icon = toggle.querySelector(".toggle-icon");
            const isHidden = input.type === "password";

            // Change input type
            input.type = isHidden ? "text" : "password";

            // Toggle the "show-password" icon state
            icon.classList.toggle("show-password", isHidden);

            // // Add small animation
            // toggle.style.transform = "scale(0.9)";
            // setTimeout(() => {
            //     toggle.style.transform = "scale(1)";
            // }, 150);

            // input.focus();
        });
    }

    // ✅ Apply toggle for both password fields
    setupPasswordToggle("password1", "passwordToggle1");
    setupPasswordToggle("password2", "passwordToggle2");
    setupPasswordToggle("password3", "passwordToggle3");

    // // ✅ Fix autofill background color (Chrome autofill issue)
    // const style = document.createElement("style");
    // style.innerHTML = `
    //     input:-webkit-autofill {
    //         -webkit-box-shadow: 0 0 0px 1000px rgb(34, 34, 34) inset !important;
    //         -webkit-text-fill-color: #fff !important;
    //         caret-color: #fff !important;
    //         transition: background-color 5000s ease-in-out 0s !important;
    //     }
    // `;
    // document.head.appendChild(style);
});



// function validateEmail() {
//     const emailInput = document.getElementById('email');
//     const email = emailInput.value.trim();
//     const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;

//     if (!email) {
//         showError('email', 'Email is required');
//         return false;
//     }

//     if (!emailRegex.test(email)) {
//         showError('email', 'Enter a valid email address');
//         return false;
//     }

//     clearError('email');
//     return true;
// }

// function validatePassword() {
//     const password = document.getElementById('password1').value;
//     const password2 = document.getElementById('password2').value;

//     if (!password) {
//         showError('password', 'Password is required');
//         return false;
//     }

//     if (password.length < 8) {
//         showError('password', 'Password must be at least 8 characters');
//         return false;
//     }

//     if (password === password2) {
//         showError('password', 'Passwords do not match');
//         return false;
//     }

//     clearError('password');
//     return true;
// }

// function showError(field, message) {
//     const formGroup = document.getElementById(field).closest('.form-group');
//     const errorElement = document.getElementById(`${field}Error`);

//     formGroup.classList.add('error');
//     errorElement.textContent = message;
//     errorElement.classList.add('show');

//     // Material-style shake animation
//     const input = document.getElementById(field);
//     input.style.animation = 'materialShake 0.4s ease-in-out';
//     setTimeout(() => {
//         input.style.animation = '';
//     }, 400);
// }

// function clearError(field) {
//     const formGroup = document.getElementById(field).closest('.form-group');
//     const errorElement = document.getElementById(`${field}Error`);

//     formGroup.classList.remove('error');
//     errorElement.classList.remove('show');
//     setTimeout(() => {
//         errorElement.textContent = '';
//     }, 200);
// }

// function handleSubmit(e) {
//     e.preventDefault();

//     const isEmailValid = validateEmail();
//     const isPasswordValid = validatePassword();

//     if (!isEmailValid || !isPasswordValid) {
//         alert('✅ Login successful!');
//         return true;
//     }
//     else{
//         alert('❌ Login failed!');
//         return false;
//     }
// }
// const loginForm = document.getElementById('loginForm');

// loginForm.addEventListener('submit', handleSubmit(e))




// function handleSocialLogin(provider, button) {
//     console.log(`Initiating ${provider} sign-in...`);
//     button.style.pointerEvents = 'none';
//     button.style.opacity = '0.7';

//     setTimeout(() => {
//         console.log(`Redirecting to ${provider} authentication...`);
//         button.style.pointerEvents = 'auto';
//         button.style.opacity = '1';
//     }, 1500);
// }

// function setLoading(state) {
//     const submitButton = document.getElementById('submitBtn');
//     if (state) {
//         submitButton.disabled = true;
//         submitButton.innerText = 'Signing in...';
//     } else {
//         submitButton.disabled = false;
//         submitButton.innerText = 'SIGN IN';
//     }
// }

// function showMaterialSuccess() {
//     alert('✅ Login successful!');
// }
