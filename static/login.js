document.addEventListener('DOMContentLoaded', () => {
    // Function to get CSRF token
    async function getCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            if (!data.token) {
                throw new Error('No token in response');
            }
            return data.token;
        } catch (error) {
            console.error('Error getting CSRF token:', error);
            const errorDiv = document.getElementById('error');
            if (errorDiv) {
                errorDiv.textContent = 'Server connection error. Please try again.';
                errorDiv.style.display = 'block';
            }
            return null;
        }
    }

    // Handle login form submission
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errorDiv = document.getElementById('error');
        errorDiv.style.display = 'none';

        try {
            const csrfToken = await getCsrfToken();
            if (!csrfToken) {
                throw new Error('Could not get CSRF token');
            }

            const response = await fetch('/api/auth/login', {
                method: 'POST',
                credentials: 'include',
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
            console.error('Login error:', error);
            errorDiv.textContent = error.message || 'An error occurred. Please try again.';
            errorDiv.style.display = 'block';
        }
    });
});