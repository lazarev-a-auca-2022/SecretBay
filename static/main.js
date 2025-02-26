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
            const response = await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });
            
            // Handle non-OK responses
            if (!response.ok) {
                // Try to parse error message
                let errorMessage;
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.error;
                } catch (e) {
                    errorMessage = `Request failed with status ${response.status}`;
                }
                throw new Error(errorMessage);
            }
            
            return response;
        } catch (error) {
            console.warn(`Attempt ${i + 1} failed:`, error);
            if (i === retries - 1) throw error;
            // Exponential backoff
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * Math.pow(2, i)));
        }
    }
}

// Check if we're on the VPN setup page
function isVPNSetupPage() {
    return window.location.pathname === '/' || window.location.pathname === '/index.html';
}

// Wait for DOM content to be fully loaded and initialize the form
function waitForElement(selector, timeout = 2000) {
    return new Promise((resolve, reject) => {
        const element = document.querySelector(selector);
        if (element) {
            resolve(element);
            return;
        }

        const observer = new MutationObserver(() => {
            const element = document.querySelector(selector);
            if (element) {
                observer.disconnect();
                resolve(element);
            }
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });

        // Timeout after specified duration
        setTimeout(() => {
            observer.disconnect();
            reject(new Error(`Element ${selector} not found after ${timeout}ms`));
        }, timeout);
    });
}

// Initialize form handling
async function initializeVPNForm() {
    if (!isVPNSetupPage()) {
        return;
    }

    try {
        // Wait for all required elements
        const form = await waitForElement('#vpnForm');
        const elements = {
            form,
            result: await waitForElement('#result'),
            error: await waitForElement('#downloadError'),
            loading: document.querySelector('#loading'), // Optional
            serverIp: await waitForElement('#serverIp'),
            username: await waitForElement('#username'),
            authMethod: await waitForElement('#authMethod'),
            authCredential: await waitForElement('#authCredential'),
            vpnType: await waitForElement('#vpnType')
        };

        // Attach submit handler once we have all elements
        elements.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            elements.result.style.display = 'none';
            elements.error.style.display = 'none';
            if (elements.loading) elements.loading.style.display = 'block';

            try {
                const formData = {
                    server_ip: elements.serverIp.value || '',
                    username: elements.username.value || '',
                    auth_method: elements.authMethod.value || '',
                    auth_credential: elements.authCredential.value || '',
                    vpn_type: elements.vpnType.value || ''
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
    } catch (error) {
        console.error('Form initialization error:', error);
    }
}

// Initialize authentication and form on page load
async function init() {
    if (!isVPNSetupPage()) {
        return;
    }

    try {
        // Check auth status with proper headers and no keep-alive
        const authResponse = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Origin': window.location.origin,
                'Connection': 'close'
            },
            credentials: 'include',
            cache: 'no-cache',
            keepalive: false
        });

        const authData = await authResponse.json();
        console.log('Auth status response:', authData);

        if (authData?.enabled && !authData?.authenticated) {
            window.location.replace('/login.html');
            return;
        }

        // Initialize form only after successful auth check
        await initializeVPNForm();
    } catch (error) {
        console.error('Auth check failed:', error);
        // Continue with form initialization despite auth failure
        await initializeVPNForm();
    }
}

// Remove the problematic startInit() call that was causing duplicate initialization
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}