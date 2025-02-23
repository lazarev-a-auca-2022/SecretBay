// Authentication and CSRF token management
let csrfToken = null;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

document.addEventListener('DOMContentLoaded', async () => {
    // Check auth status first before doing anything else
    try {
        const response = await fetch('/api/auth/status', {
            headers: { 'Accept': 'application/json' }
        });
        
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
            const statusResponse = await fetch('/api/vpn/status', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });

            if (statusResponse.status === 401 || statusResponse.status === 403) {
                localStorage.removeItem('jwt');
                window.location.href = '/login.html';
                return;
            }
        }

        // Initialize form handling only after auth check passes
        const vpnForm = document.getElementById('vpnForm');
        if (vpnForm) {
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
        
    } catch (error) {
        console.error('Auth check error:', error);
        window.location.href = '/error/backend-down.html';
    }
});