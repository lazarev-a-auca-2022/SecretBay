document.addEventListener('DOMContentLoaded', () => {
    // Function to get CSRF token
    async function getCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Failed to get CSRF token');
            }
            
            const data = await response.json();
            return data.token;
        } catch (error) {
            console.error('Error getting CSRF token:', error);
            const errorDiv = document.getElementById('error');
            if (errorDiv) {
                errorDiv.textContent = 'Authentication error. Please try again.';
                errorDiv.style.display = 'block';
            }
            return null;
        }
    }

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errorDiv = document.getElementById('error');
        errorDiv.style.display = 'none';

        try {
            // Get CSRF token first
            const csrfToken = await getCsrfToken();
            if (!csrfToken) {
                throw new Error('Could not get CSRF token');
            }

            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('jwt', data.token);
                window.location.href = '/';
            } else {
                const error = await response.json();
                errorDiv.textContent = error.error || 'Login failed';
                errorDiv.style.display = 'block';
            }
        } catch (error) {
            errorDiv.textContent = 'An error occurred. Please try again.';
            errorDiv.style.display = 'block';
        }
    });
});