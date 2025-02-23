// Authentication check on page load
window.addEventListener('load', async () => {
    try {
        // Check if auth is enabled
        const authCheckResponse = await fetch('/api/auth/status');
        const authData = await authCheckResponse.json();
        
        if (!authData.enabled) {
            // If auth is disabled, no need to check for token
            return;
        }

        const token = localStorage.getItem('jwt');
        if (!token) {
            window.location.href = '/login.html';
            return;
        }
        
        const response = await fetch('/api/vpn/status', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html?auth_error=true';
            return;
        }

        if (!response.ok) {
            console.error('Error checking authentication:', response.status);
            // Don't redirect for non-auth related errors
            return;
        }

        // Successfully authenticated, ensure we're on the right page
        if (window.location.pathname === '/login.html') {
            window.location.replace('/');
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // Only redirect on auth errors, not network errors
        if (error.name === 'AuthenticationError' || (error.response && (error.response.status === 401 || error.response.status === 403))) {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html?auth_error=true';
        }
    }
});

// Authentication and CSRF token management
let csrfToken = null;

async function getCsrfToken() {
    try {
        const response = await fetch('/api/csrf-token', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Cache-Control': 'no-cache'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Expected JSON response but got ' + contentType);
        }
        
        const data = await response.json();
        if (!data.token) {
            throw new Error('No token in response');
        }
        csrfToken = data.token;
        return csrfToken;
    } catch (error) {
        console.error('Error getting CSRF token:', error);
        return null;
    }
}

// Function to get JWT token with CSRF support
async function getJWTToken() {
    let token = localStorage.getItem('jwt');
    if (!token) {
        try {
            // Get CSRF token first
            const csrfToken = await getCsrfToken();
            if (!csrfToken) {
                throw new Error('Failed to get CSRF token');
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
            
            if (!response.ok) {
                throw new Error('Authentication failed');
            }
            
            const data = await response.json();
            token = data.token;
            localStorage.setItem('jwt', token);
        } catch (error) {
            console.error('Error getting JWT token:', error);
            return null;
        }
    }
    return token;
}

// Function to check if token is valid
async function isTokenValid(token) {
    try {
        const response = await fetch('/api/vpn/status', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        return response.status === 200;
    } catch (error) {
        return false;
    }
}

// Handle form submission with CSRF protection
document.getElementById('vpnForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('downloadError');
    resultDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    try {
        // Get fresh CSRF token
        const csrfToken = await getCsrfToken();
        if (!csrfToken) {
            throw new Error('Could not get CSRF token');
        }

        let token = await getJWTToken();
        if (!token || !(await isTokenValid(token))) {
            localStorage.removeItem('jwt');
            token = await getJWTToken();
            if (!token) {
                throw new Error('Could not authenticate. Please try again.');
            }
        }

        // Setup VPN
        const response = await fetch('/api/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({
                server_ip: document.getElementById('serverIp').value,
                username: document.getElementById('username').value,
                auth_method: document.getElementById('authMethod').value,
                auth_credential: document.getElementById('authCredential').value,
                vpn_type: document.getElementById('vpnType').value
            })
        });

        const data = await response.json();
        if (response.ok) {
            resultDiv.textContent = 'VPN setup successful! Downloading configuration...';
            resultDiv.style.color = 'green';
            resultDiv.style.display = 'block';

            // Automatically download the config
            const downloadResponse = await fetch(`/api/config/download?server_ip=${encodeURIComponent(document.getElementById('serverIp').value)}&username=${encodeURIComponent(document.getElementById('username').value)}&credential=${encodeURIComponent(document.getElementById('authCredential').value)}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-CSRF-Token': csrfToken
                }
            });

            if (!downloadResponse.ok) {
                throw new Error('Failed to download configuration');
            }

            const blob = await downloadResponse.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = "vpn_config";
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);

            resultDiv.textContent += '\nConfiguration downloaded successfully!';
        } else {
            throw new Error(data.error || 'Failed to setup VPN');
        }
    } catch (error) {
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
        resultDiv.style.display = 'none';
    }
});