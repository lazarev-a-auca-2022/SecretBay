document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const errorDiv = document.getElementById('error');
    const successDiv = document.getElementById('success');

    // Don't check token on login page to prevent redirect loops
    const token = localStorage.getItem('jwt');
    if (token) {
        localStorage.removeItem('jwt'); // Clear any existing token on login page
    }
    
    // Check for registration success message
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('registered') === 'true') {
        successDiv.textContent = 'Registration successful! Please login.';
        successDiv.style.display = 'block';
    }

    // Function to get CSRF token with retries
    async function getCsrfToken(retries = 3) {
        for (let i = 0; i < retries; i++) {
            try {
                const response = await fetch('/api/csrf-token', {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-cache'
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
                console.error(`CSRF token fetch attempt ${i + 1} failed:`, error);
                if (i === retries - 1) {
                    throw error;
                }
                // Wait before retrying, with exponential backoff
                await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
            }
        }
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';

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

            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.error || `Login failed: ${response.status}`);
            }

            const data = await response.json();
            if (data.token) {
                localStorage.setItem('jwt', data.token);
                window.location.replace('/');
            } else {
                throw new Error('Invalid response from server');
            }
        } catch (error) {
            console.error('Login error:', error);
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
            localStorage.removeItem('jwt'); // Clear token on error
        }
    });
});