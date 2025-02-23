// Authentication and CSRF token management
let csrfToken = null;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second
const MAX_STARTUP_ATTEMPTS = 5; // Maximum attempts to wait for server startup
const STARTUP_CHECK_INTERVAL = 2000; // 2 seconds between startup checks

document.addEventListener('DOMContentLoaded', () => {
    // Helper function to delay execution
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
    
    // Helper function to check if server is ready
    async function waitForServer(attempts = 0) {
        try {
            const response = await fetch('/api/auth/status', {
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            // If we get HTML instead of JSON, handle it gracefully
            const contentType = response.headers.get('content-type');
            if (contentType && !contentType.includes('application/json')) {
                // If auth is enabled, redirect to login
                if (response.status === 303) {
                    window.location.href = '/login.html';
                    return false;
                }
                // Otherwise try to continue
                return true;
            }

            const data = await response.json();
            // If auth is disabled, allow access
            if (data.hasOwnProperty('enabled') && !data.enabled) {
                return true;
            }

            return response.ok;
        } catch (error) {
            console.error('Error checking server:', error);
            if (attempts < MAX_STARTUP_ATTEMPTS) {
                await delay(STARTUP_CHECK_INTERVAL);
                return waitForServer(attempts + 1);
            }
            window.location.href = '/error/backend-down.html';
            return false;
        }
    }

    // Helper function to handle network requests with retries
    async function fetchWithRetries(url, options = {}, retryCount = 0) {
        try {
            const response = await fetch(url, options).catch(error => {
                throw new Error('Could not connect to server');
            });
            
            if (!response || !response.headers) {
                throw new Error('Invalid server response');
            }

            // Handle redirects explicitly
            if (response.status === 303) {
                const location = response.headers.get('Location');
                if (location && location.includes('login.html')) {
                    window.location.href = location;
                    return null;
                }
            }

            const contentType = response.headers.get('content-type');
            
            // If we get HTML when expecting JSON, it might be an error page
            if (options.headers?.Accept === 'application/json' && 
                (!contentType || !contentType.includes('application/json'))) {
                
                const text = await response.text();
                if (text.includes('<!DOCTYPE')) {
                    if (retryCount < MAX_RETRIES) {
                        console.log(`Retrying request to ${url}... (${retryCount + 1}/${MAX_RETRIES})`);
                        await delay(RETRY_DELAY * Math.pow(2, retryCount)); // Exponential backoff
                        return fetchWithRetries(url, options, retryCount + 1);
                    }
                    window.location.href = '/error/backend-down.html';
                    return null;
                }
                throw new Error('Unexpected response type');
            }
            
            return response;
        } catch (error) {
            if (retryCount < MAX_RETRIES) {
                console.log(`Retrying request to ${url}... (${retryCount + 1}/${MAX_RETRIES})`);
                await delay(RETRY_DELAY * Math.pow(2, retryCount)); // Exponential backoff
                return fetchWithRetries(url, options, retryCount + 1);
            }
            throw error;
        }
    }

    async function getCsrfToken() {
        try {
            const response = await fetchWithRetries('/api/csrf-token', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });

            if (!response) {
                return null; // Already redirected to error page
            }

            const data = await response.json();
            if (!data || !data.token) {
                throw new Error('No token in response');
            }
            csrfToken = data.token;
            return csrfToken;
        } catch (error) {
            console.error('Error getting CSRF token:', error);
            if (error.message.includes('Could not connect')) {
                window.location.href = '/error/backend-down.html';
            } else {
                window.location.href = '/login.html';
            }
            return null;
        }
    }

    async function getJWTToken() {
        const token = localStorage.getItem('jwt');
        if (!token) {
            window.location.href = '/login.html';
            return null;
        }
        return token;
    }

    async function isTokenValid(token) {
        try {
            const response = await fetchWithRetries('/api/vpn/status', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });
            
            return response ? response.ok : false;
        } catch (error) {
            return false;
        }
    }

    // Authentication check on page load
    (async () => {
        try {
            // First check if server is ready
            if (!await waitForServer()) {
                return; // Already redirected to error page
            }

            // Try to get initial authentication status
            const response = await fetchWithRetries('/api/auth/status', {
                headers: {
                    'Accept': 'application/json'
                }
            }).catch(() => null);

            if (!response) {
                window.location.href = '/error/backend-down.html';
                return;
            }

            const authData = await response.json();
            if (!authData.enabled) {
                return;
            }

            const token = localStorage.getItem('jwt');
            if (!token) {
                window.location.href = '/login.html';
                return;
            }

            const statusResponse = await fetchWithRetries('/api/vpn/status', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });

            if (!statusResponse) {
                return; // Already redirected to error page
            }

            if (statusResponse.status === 401 || statusResponse.status === 403) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html?auth_error=true';
                return;
            }

            if (!statusResponse.ok) {
                throw new Error(`Status check failed: ${statusResponse.status}`);
            }
        } catch (error) {
            console.error('Authentication check error:', error);
            if (error.message?.includes('Could not connect')) {
                window.location.href = '/error/backend-down.html';
            } else {
                window.location.href = '/login.html';
            }
        }
    })();

    // Only initialize VPN form if we're on the main page
    const vpnForm = document.getElementById('vpnForm');
    if (vpnForm && window.location.pathname === '/') {
        vpnForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const resultDiv = document.getElementById('result');
            const errorDiv = document.getElementById('downloadError');
            
            if (!resultDiv || !errorDiv) {
                console.error('Required DOM elements not found');
                return;
            }

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
                const setupResponse = await fetchWithRetries('/api/setup', {
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

                if (!setupResponse) {
                    return; // Already redirected to error page
                }

                const setupData = await setupResponse.json();
                if (!setupResponse.ok) {
                    throw new Error(setupData.error || 'Failed to setup VPN');
                }

                resultDiv.textContent = 'VPN setup successful! Downloading configuration...';
                resultDiv.style.color = 'green';
                resultDiv.style.display = 'block';

                // Automatically download the config
                const downloadResponse = await fetchWithRetries(`/api/config/download?server_ip=${encodeURIComponent(document.getElementById('serverIp').value)}&username=${encodeURIComponent(document.getElementById('username').value)}&credential=${encodeURIComponent(document.getElementById('authCredential').value)}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'X-CSRF-Token': csrfToken
                    }
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
                if (error.message?.includes('Could not connect')) {
                    window.location.href = '/error/backend-down.html';
                } else {
                    errorDiv.textContent = error.message || 'An unexpected error occurred';
                    errorDiv.style.display = 'block';
                    resultDiv.style.display = 'none';
                }
            }
        });
    }
});