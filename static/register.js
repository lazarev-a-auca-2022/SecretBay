document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const errorDiv = document.getElementById('error');

    async function getCsrfToken() {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        return data.token;
    }

    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        errorDiv.textContent = '';

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    username,
                    email,
                    password
                })
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Registration failed');
            }

            // Registration successful, redirect to login
            window.location.href = '/login.html?registered=true';
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        }
    });
});