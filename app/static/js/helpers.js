// Toggle password visibility
function togglePasswordVisibility(button) {
    var passwordField = button.previousElementSibling;
    var icon = button.querySelector("ion-icon");

    if (passwordField.type === "password") {
        passwordField.type = "text";
        icon.setAttribute("name", "eye");
    } else {
        passwordField.type = "password";
        icon.setAttribute("name", "eye-off");
    }
}


// Calculate the layout if flash message is present
window.addEventListener("load", function() {
    var navbar = document.getElementById("navbar");
    var flashMessage = document.getElementById("flash-message");
    var main = document.getElementById("main");

    if (flashMessage) {
        var navbarHeight = navbar.offsetHeight + 5;

        flashMessage.style.marginTop = navbarHeight + "px";
        main.style.marginTop = `calc(6rem - ${navbarHeight}px)`;
        console.log(flashMessage.style.marginTop);

        setTimeout(function() {
            flashMessage.style.display = "none";
            main.style.marginTop = "6rem";
        }, 10000);

    }
});
