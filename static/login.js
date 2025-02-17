document.addEventListener('DOMContentLoaded', () => {
    // Function to get CSRF token
    async function getCsrfToken() {
        try {
            // Ensure we're using HTTPS for all requests
            const protocol = window.location.protocol;
            const host = window.location.host;
            const url = `${protocol}//${host}/api/csrf-token`;

            console.log('Fetching CSRF token from:', url); // Debug log

            const response = await fetch(url, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('CSRF token error:', errorText); // Debug log
                throw new Error(errorText || 'Failed to get CSRF token');
            }
            
            const data = await response.json();
            console.log('CSRF token received:', data.token ? 'Yes' : 'No'); // Debug log
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

    // Handle login form submission
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

            const protocol = window.location.protocol;
            const host = window.location.host;
            const loginUrl = `${protocol}//${host}/api/auth/login`;

            const response = await fetch(loginUrl, {
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
            console.error('Login error:', error); // Debug log
            errorDiv.textContent = 'An error occurred. Please try again.';
            errorDiv.style.display = 'block';
        }
    });
});