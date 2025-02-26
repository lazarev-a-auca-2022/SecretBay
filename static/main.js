// Basic HTTP retry functionality
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000;

// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

// Helper function for retrying failed requests
async function fetchWithRetries(url, options, retries = MAX_RETRIES) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.error || `Request failed with status ${response.status}`);
            }
            return response;
        } catch (error) {
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * Math.pow(2, i)));
        }
    }
}

// Check if we're on the VPN setup page
function isVPNSetupPage() {
    return window.location.pathname === '/' || window.location.pathname === '/index.html';
}

// Initialize form handling
function initializeVPNForm() {
    // Only initialize if we're on the VPN setup page
    if (!isVPNSetupPage()) {
        return;
    }

    // Wait for DOM to be fully loaded
    const initForm = () => {
        // Pre-check if form exists to avoid null issues
        if (!document.getElementById('vpnForm')) {
            if (window.initRetries === undefined) {
                window.initRetries = 0;
            }
            
            if (window.initRetries < 10) {
                window.initRetries++;
                setTimeout(initForm, 100);
                return;
            }
            console.error('VPN form not found after maximum retries');
            return;
        }

        const elements = {
            form: document.getElementById('vpnForm'),
            result: document.getElementById('result'),
            error: document.getElementById('downloadError'),
            loading: document.getElementById('loading'),
            serverIp: document.getElementById('serverIp'),
            username: document.getElementById('username'),
            authMethod: document.getElementById('authMethod'),
            authCredential: document.getElementById('authCredential'),
            vpnType: document.getElementById('vpnType')
        };

        // Verify all required elements exist
        const requiredElements = ['form', 'result', 'error'];
        const missingElements = requiredElements.filter(el => !elements[el]);
        
        if (missingElements.length > 0) {
            console.error('Missing required elements:', missingElements.join(', '));
            return;
        }

        // Reset retry counter since we found the form
        window.initRetries = 0;

        // Attach submit handler
        elements.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            elements.result.style.display = 'none';
            elements.error.style.display = 'none';
            if (elements.loading) elements.loading.style.display = 'block';

            try {
                const formData = {
                    server_ip: elements.serverIp?.value || '',
                    username: elements.username?.value || '',
                    auth_method: elements.authMethod?.value || '',
                    auth_credential: elements.authCredential?.value || '',
                    vpn_type: elements.vpnType?.value || ''
                };

                // Setup VPN
                const setupResponse = await fetchWithRetries(`${BASE_URL}/api/setup`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'Origin': window.location.origin
                    },
                    credentials: 'include',
                    body: JSON.stringify(formData)
                });

                if (!setupResponse.ok) {
                    const setupData = await setupResponse.json();
                    throw new Error(setupData.error || 'Failed to setup VPN');
                }

                elements.result.textContent = 'VPN setup successful! Downloading configuration...';
                elements.result.style.color = 'green';
                elements.result.style.display = 'block';

                // Download config
                const downloadResponse = await fetchWithRetries(
                    `${BASE_URL}/api/config/download?` + new URLSearchParams({
                        server_ip: formData.server_ip,
                        username: formData.username,
                        credential: formData.auth_credential
                    }),
                    {
                        headers: {
                            'Accept': 'application/octet-stream',
                            'Origin': window.location.origin
                        },
                        credentials: 'include'
                    }
                );

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

                elements.result.textContent += '\nConfiguration downloaded successfully!';
            } catch (error) {
                console.error('Setup error:', error);
                if (error.message?.includes('Could not connect') || error.message?.includes('Network error')) {
                    window.location.href = '/error/backend-down.html';
                } else {
                    elements.error.textContent = error.message || 'An unexpected error occurred';
                    elements.error.style.display = 'block';
                    elements.result.style.display = 'none';
                }
            } finally {
                if (elements.loading) elements.loading.style.display = 'none';
            }
        });
    };

    // Start the initialization
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initForm);
    } else {
        initForm();
    }
}

// Initialize form on page load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Check authentication status only on the VPN setup page
        if (isVPNSetupPage()) {
            try {
                const authResponse = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
                    headers: {
                        'Accept': 'application/json',
                        'Origin': window.location.origin
                    },
                    credentials: 'include'
                });

                const authData = await authResponse.json();
                if (authData?.enabled && !authData?.authenticated) {
                    window.location.replace('/login.html');
                    return;
                }
            } catch (error) {
                console.warn('Auth status check failed:', error);
                // Don't redirect on auth check failure, just continue with form initialization
            }
        }

        // Initialize the form
        initializeVPNForm();
    } catch (error) {
        console.error('Initialization error:', error);
        // Continue with form initialization even if auth check fails
        initializeVPNForm();
    }
});