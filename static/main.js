// Authentication and CSRF token management
let csrfToken = null;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

document.addEventListener('DOMContentLoaded', async () => {
    // Check auth status first before doing anything else
    try {
        const response = await fetch(`${BASE_URL}/api/auth/status`, {
            headers: { 
                'Accept': 'application/json',
                'Origin': window.location.origin
            },
            credentials: 'include'
        }).catch(error => {
            console.error('Failed to connect to server:', error);
            window.location.href = '/error/backend-down.html';
            return null;
        });

        if (!response) return; // Already redirected due to connection error
        
        // Check if response is HTML instead of JSON
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
            window.location.href = '/error/backend-down.html';
            return;
        }

        if (!response.ok) {
            throw new Error('Server error');
        }

        const data = await response.json();
        
        // Only proceed with auth checks if auth is enabled
        if (data.enabled) {
            const token = localStorage.getItem('jwt');
            if (!token) {
                window.location.href = '/login.html';
                return;
            }

            // Verify token is valid
            const statusResponse = await fetch(`${BASE_URL}/api/vpn/status`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                    'Origin': window.location.origin
                },
                credentials: 'include'
            }).catch(error => {
                console.error('Failed to check token status:', error);
                window.location.href = '/error/backend-down.html';
                return null;
            });

            if (!statusResponse) return; // Already redirected due to connection error

            // Check if response is HTML instead of JSON
            const statusContentType = statusResponse.headers.get('content-type');
            if (statusContentType && statusContentType.includes('text/html')) {
                window.location.href = '/error/backend-down.html';
                return;
            }

            if (statusResponse.status === 401 || statusResponse.status === 403) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html';
                return;
            }
        }

        // Initialize form handling only after auth check passes
        const vpnForm = document.getElementById('vpnForm');
        // Early return if we're not on a page with the VPN form
        if (!vpnForm) {
            console.log('VPN form not found - likely on a different page');
            return;
        }

        const resultDiv = document.getElementById('result');
        const errorDiv = document.getElementById('downloadError');
        
        if (!resultDiv || !errorDiv) {
            console.error('Required DOM elements not found');
            return;
        }

        vpnForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            resultDiv.style.display = 'none';
            errorDiv.style.display = 'none';

            try {
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
                const setupResponse = await fetchWithRetries(`${BASE_URL}/api/setup`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`,
                        'X-CSRF-Token': csrfToken,
                        'Accept': 'application/json',
                        'Origin': window.location.origin
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        server_ip: document.getElementById('serverIp')?.value || '',
                        username: document.getElementById('username')?.value || '',
                        auth_method: document.getElementById('authMethod')?.value || '',
                        auth_credential: document.getElementById('authCredential')?.value || '',
                        vpn_type: document.getElementById('vpnType')?.value || ''
                    })
                }).catch(error => {
                    console.error('Failed to setup VPN:', error);
                    window.location.href = '/error/backend-down.html';
                    return null;
                });

                if (!setupResponse) return; // Already redirected due to connection error

                // Check for HTML response
                const setupContentType = setupResponse.headers.get('content-type');
                if (setupContentType && setupContentType.includes('text/html')) {
                    window.location.href = '/error/backend-down.html';
                    return;
                }

                const setupData = await setupResponse.json().catch(err => {
                    console.error('Failed to parse JSON:', err);
                    window.location.href = '/error/backend-down.html';
                    return null;
                });

                if (!setupData) return;

                if (!setupResponse.ok) {
                    throw new Error(setupData.error || 'Failed to setup VPN');
                }

                resultDiv.textContent = 'VPN setup successful! Downloading configuration...';
                resultDiv.style.color = 'green';
                resultDiv.style.display = 'block';

                // Automatically download the config
                const serverIp = document.getElementById('serverIp')?.value || '';
                const username = document.getElementById('username')?.value || '';
                const credential = document.getElementById('authCredential')?.value || '';

                const downloadResponse = await fetchWithRetries(`${BASE_URL}/api/config/download?server_ip=${encodeURIComponent(serverIp)}&username=${encodeURIComponent(username)}&credential=${encodeURIComponent(credential)}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'X-CSRF-Token': csrfToken,
                        'Origin': window.location.origin
                    },
                    credentials: 'include'
                }).catch(error => {
                    console.error('Failed to download config:', error);
                    throw new Error('Failed to download configuration: Network error');
                });

                if (!downloadResponse || !downloadResponse.ok) {
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
                console.error('Setup error:', error);
                if (error.message?.includes('Could not connect') || error.message?.includes('Network error')) {
                    window.location.href = '/error/backend-down.html';
                } else {
                    errorDiv.textContent = error.message || 'An unexpected error occurred';
                    errorDiv.style.display = 'block';
                    resultDiv.style.display = 'none';
                }
            }
        });
        
    } catch (error) {
        console.error('Auth check error:', error);
        window.location.href = '/error/backend-down.html';
    }
});