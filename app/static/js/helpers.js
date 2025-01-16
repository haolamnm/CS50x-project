// Toggle password visibility
function togglePasswordVisibility(button) {
    var passwordField = button.previousElementSibling;
    var icon = button.querySelector("i");

    if (passwordField.type === "password") {
        passwordField.type = "text";
        icon.setAttribute("class", "fa-solid fa-eye m");
    } else {
        passwordField.type = "password";
        icon.setAttribute("class", "fa-solid fa-eye-slash");
    }
}


// Timeout the flash message after 10 seconds, with DOM Loaded
document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function () {
        var flashMessage = document.getElementById("flash-message");
        if (flashMessage) {
            flashMessage.remove();
        }
    }, 10000);
});
