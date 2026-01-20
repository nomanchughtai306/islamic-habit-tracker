/**
 * Mumin Path - Global Interactions
 * Handles: Flash Messages, Password Toggles, Mobile Menu, and UI Polish
 */

document.addEventListener('DOMContentLoaded', function() {
    
    // 1. AUTO-HIDE FLASH MESSAGES
    // Automatically fades out notification messages after 5 seconds
    const flashes = document.querySelectorAll('.flashes li');
    flashes.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            message.style.transform = 'translateY(-20px)';
            message.style.transition = 'all 0.6s cubic-bezier(0.16, 1, 0.3, 1)';
            
            // Remove from DOM after animation finishes
            setTimeout(() => {
                message.remove();
            }, 600);
        }, 5000);
    });

    // 2. MOBILE MENU TOGGLE
    // Handles the logic for the hamburger menu on smaller screens
    const menuToggle = document.getElementById('menu-toggle');
    const navLinks = document.querySelector('.nav-links');
    
    if (menuToggle) {
        menuToggle.addEventListener('change', function() {
            if (this.checked) {
                navLinks.style.display = 'flex';
                // Add a small delay for the fade-in effect
                setTimeout(() => { navLinks.style.opacity = '1'; }, 10);
            } else {
                navLinks.style.opacity = '0';
                setTimeout(() => { navLinks.style.display = 'none'; }, 300);
            }
        });
    }

    // 3. SMOOTH SCROLLING
    // Makes internal anchor links scroll smoothly
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // 4. FORM SUBMISSION LOADING STATE
    // Prevents double-clicking buttons and gives visual feedback
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const btn = this.querySelector('button[type="submit"]');
            if (btn) {
                btn.style.opacity = '0.7';
                btn.style.pointerEvents = 'none';
                btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Processing...';
            }
        });
    });
});

// 5. PASSWORD VISIBILITY TOGGLE (Global Version)
// Can be called from any login/register/edit profile page
function togglePassword() {
    const passwordInput = document.getElementById("password");
    const eyeIcon = document.getElementById("eyeIcon");
    
    if (!passwordInput || !eyeIcon) return;

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.classList.remove("fa-regular", "fa-eye");
        eyeIcon.classList.add("fa-solid", "fa-eye-slash");
        eyeIcon.style.color = "var(--gold)";
    } else {
        passwordInput.type = "password";
        eyeIcon.classList.remove("fa-solid", "fa-eye-slash");
        eyeIcon.classList.add("fa-regular", "fa-eye");
        eyeIcon.style.color = "var(--text-dim)";
    }
}

// 6. FILE NAME PREVIEW (For Profile Picture Upload)
const fileInput = document.getElementById('profile-upload');
if (fileInput) {
    fileInput.addEventListener('change', function() {
        const fileNameDisplay = document.getElementById('file-name');
        if (this.files && this.files.length > 0) {
            fileNameDisplay.innerText = "Selected: " + this.files[0].name;
            fileNameDisplay.style.color = "var(--gold)";
            fileNameDisplay.style.fontWeight = "bold";
        }
    });
}