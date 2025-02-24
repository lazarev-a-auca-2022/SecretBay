// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const errorDiv = document.getElementById('error');

    async function getCsrfToken(retries = 3) {
        for (let i = 0; i < retries; i++) {
            try {
                const response = await fetch(`${BASE_URL}/api/csrf-token`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Accept': 'application/json',
                        'Origin': window.location.origin,
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

    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        errorDiv.textContent = '';
        errorDiv.style.display = 'none';

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        try {
            const csrfToken = await getCsrfToken();
            if (!csrfToken) {
                throw new Error('Could not get CSRF token');
            }

            const response = await fetch(`${BASE_URL}/api/auth/register`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                    'Accept': 'application/json',
                    'Origin': window.location.origin
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