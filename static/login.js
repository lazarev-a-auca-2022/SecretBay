// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

document.addEventListener('DOMContentLoaded', async () => {
    const loginForm = document.getElementById('loginForm');
    const errorDiv = document.getElementById('error');
    const successDiv = document.getElementById('success');

    // Clear any existing tokens if we're on the login page
    // but keep token if we just registered successfully
    const urlParams = new URLSearchParams(window.location.search);
    if (!urlParams.get('registered')) {
        localStorage.removeItem('jwt');
    }

    // First check if authentication is enabled
    try {
        const token = localStorage.getItem('jwt');
        const headers = {
            'Accept': 'application/json',
            'Origin': window.location.origin
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const authCheckResponse = await fetch(`${BASE_URL}/api/auth/status`, {
            headers: headers,
            credentials: 'include'
        });
        const authData = await authCheckResponse.json();
        
        if (!authData.enabled) {
            // If auth is disabled, redirect to main page
            window.location.replace('/');
            return;
        }

        // If we're already authenticated and not here due to an error, redirect to main page
        if (token && authData.authenticated) {
            const urlParams = new URLSearchParams(window.location.search);
            if (!urlParams.get('auth_error')) {
                window.location.replace('/');
                return;
            }
        }
    } catch (error) {
        console.error('Error checking auth status:', error);
    }

    // Only remove token if we were redirected here due to an auth error
    if (urlParams.get('auth_error')) {
        localStorage.removeItem('jwt');
    }
    
    // Check for registration success message
    if (urlParams.get('registered') === 'true') {
        successDiv.textContent = 'Registration successful! Please login.';
        successDiv.style.display = 'block';
    }

    // Function to get CSRF token with retries
    async function getCsrfToken(retries = 3) {
        for (let i = 0; i < retries; i++) {
            try {
                const response = await fetch(`${BASE_URL}/api/csrf-token`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'Origin': window.location.origin
                    },
                    credentials: 'include'
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

    // Function to validate login response
    async function validateLoginResponse(response) {
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error || `Login failed: ${response.status}`);
        }

        const data = await response.json();
        if (!data.token) {
            throw new Error('Invalid response from server');
        }

        // Store token in localStorage
        localStorage.setItem('jwt', data.token);

        // Verify the token works by making an auth check with proper headers
        const authCheck = await fetch(`${BASE_URL}/api/auth/status`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${data.token}`,
                'Origin': window.location.origin,
                'Cache-Control': 'no-cache'
            },
            credentials: 'include'
        });

        const authData = await authCheck.json();
        if (!authData?.authenticated) {
            localStorage.removeItem('jwt');
            throw new Error('Authentication verification failed');
        }

        return data;
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

            const response = await fetch(`${BASE_URL}/api/auth/login`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                    'Accept': 'application/json',
                    'Origin': window.location.origin
                },
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });

            // Validate login and store token
            await validateLoginResponse(response);

            // Redirect to main page after successful login and validation
            window.location.replace('/');
        } catch (error) {
            console.error('Login error:', error);
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
            localStorage.removeItem('jwt'); // Clear token on error
        }
    });
});