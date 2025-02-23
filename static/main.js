// Authentication and CSRF token management
let csrfToken = null;

document.addEventListener('DOMContentLoaded', () => {
    // Authentication check on page load
    (async () => {
        try {
            // Check if auth is enabled
            const authCheckResponse = await fetch('/api/auth/status', {
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            // If we get redirected to login page, handle it gracefully
            const contentType = authCheckResponse.headers.get('content-type');
            if (contentType && contentType.includes('text/html')) {
                window.location.href = '/login.html';
                return;
            }
            
            if (!authCheckResponse.ok) {
                throw new Error(`HTTP error! status: ${authCheckResponse.status}`);
            }
            
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
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });
            
            if (response.status === 401 || response.status === 403) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html?auth_error=true';
                return;
            }

            // If we get redirected to login page, handle it gracefully
            const responseType = response.headers.get('content-type');
            if (responseType && responseType.includes('text/html')) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html';
                return;
            }

            if (!response.ok) {
                console.error('Error checking authentication:', response.status);
                return;
            }
        } catch (error) {
            console.error('Error checking authentication:', error);
            if (error.name === 'SyntaxError') {
                // If we get HTML instead of JSON, we've probably been redirected
                window.location.href = '/login.html';
                return;
            }
            // Only redirect on auth errors, not network errors
            if (error.name === 'AuthenticationError' || (error.response && (error.response.status === 401 || error.response.status === 403))) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html?auth_error=true';
            }
        }
    })();

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
            
            // Handle redirects to login page
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('text/html')) {
                window.location.href = '/login.html';
                return null;
            }
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            if (!data.token) {
                throw new Error('No token in response');
            }
            csrfToken = data.token;
            return csrfToken;
        } catch (error) {
            console.error('Error getting CSRF token:', error);
            if (error.name === 'SyntaxError') {
                // If we get HTML instead of JSON, redirect to login
                window.location.href = '/login.html';
            }
            return null;
        }
    }

    // Function to get JWT token with CSRF support
    async function getJWTToken() {
        let token = localStorage.getItem('jwt');
        if (!token) {
            window.location.href = '/login.html';
            return null;
        }
        return token;
    }

    // Function to check if token is valid
    async function isTokenValid(token) {
        try {
            const response = await fetch('/api/vpn/status', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });
            
            // Handle redirects to login page
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('text/html')) {
                return false;
            }
            
            return response.status === 200;
        } catch (error) {
            return false;
        }
    }

    // Handle form submission with CSRF protection
    const vpnForm = document.getElementById('vpnForm');
    if (vpnForm) {
        vpnForm.addEventListener('submit', async (e) => {
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
                    window.location.href = '/login.html';
                    return;
                }

                // Setup VPN
                const response = await fetch('/api/setup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`,
                        'X-CSRF-Token': csrfToken,
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        server_ip: document.getElementById('serverIp').value,
                        username: document.getElementById('username').value,
                        auth_method: document.getElementById('authMethod').value,
                        auth_credential: document.getElementById('authCredential').value,
                        vpn_type: document.getElementById('vpnType').value
                    })
                });

                // Handle redirects to login page
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('text/html')) {
                    window.location.href = '/login.html';
                    return;
                }

                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    throw new Error(data.error || 'Failed to setup VPN');
                }

                const data = await response.json();
                resultDiv.textContent = 'VPN setup successful! Downloading configuration...';
                resultDiv.style.color = 'green';
                resultDiv.style.display = 'block';

                // Automatically download the config
                const downloadResponse = await fetch(`/api/config/download?server_ip=${encodeURIComponent(document.getElementById('serverIp').value)}&username=${encodeURIComponent(document.getElementById('username').value)}&credential=${encodeURIComponent(document.getElementById('authCredential').value)}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'X-CSRF-Token': csrfToken,
                        'Accept': 'application/json'
                    }
                });

                // Handle redirects to login page
                if (downloadResponse.headers.get('content-type')?.includes('text/html')) {
                    window.location.href = '/login.html';
                    return;
                }

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
                document.body.removeChild(a);

                resultDiv.textContent += '\nConfiguration downloaded successfully!';
            } catch (error) {
                errorDiv.textContent = error.message;
                errorDiv.style.display = 'block';
                resultDiv.style.display = 'none';
            }
        });
    }
});