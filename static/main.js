// Basic HTTP retry functionality
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second base delay

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
                    'Cache-Control': 'no-cache',
                    'Connection': 'close' // Force connection close to prevent H2 issues
                }
            });
            
            // Check for specific status codes that might be successful despite not being 200
            if (!response.ok && response.status !== 204) {
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

// Helper function to check if we're on the VPN setup page
function isVPNSetupPage() {
    return document.querySelector('#vpnForm') !== null;
}

function waitForElement(selector, timeout = 5000) {
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
            // Don't reject, just resolve with null
            resolve(null);
            console.warn(`Element ${selector} not found after ${timeout}ms`);
        }, timeout);
    });
}

// Helper function to create fallback elements
function createFallbackElement(type, id) {
    const el = document.createElement(type);
    el.id = id;
    el.style.display = 'none';
    document.body.appendChild(el);
    return el;
}

async function initializeVPNForm() {
    try {
        // Wait for the form element first, and exit early if it's not present
        const form = await waitForElement('#vpnForm');
        if (!form) {
            console.log('VPN form not found on this page');
            return;
        }
        
        // Only proceed if we have the form element
        const elements = {
            form: form,
            serverIp: await waitForElement('#serverIp'),
            username: await waitForElement('#username'),
            authMethod: await waitForElement('#authMethod'),
            authCredential: await waitForElement('#authCredential'),
            vpnType: await waitForElement('#vpnType'),
            result: await waitForElement('#result') || createFallbackElement('div', 'result'),
            error: await waitForElement('#downloadError') || createFallbackElement('div', 'downloadError'),
            loading: await waitForElement('#loading') || createFallbackElement('div', 'loading')
        };

        // Check if critical elements are missing before proceeding
        if (!elements.serverIp || !elements.username || 
            !elements.authCredential || !elements.vpnType || !elements.authMethod) {
            console.error('Required form elements missing - cannot initialize form');
            return;
        }
        
        // Now safely add the event listener - we verified form is not null above
        elements.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            elements.result.style.display = 'none';
            elements.error.style.display = 'none';
            elements.loading.style.display = 'block';

            try {
                const formData = {
                    server_ip: elements.serverIp.value || '',
                    username: elements.username.value || '',
                    auth_method: elements.authMethod.value || '',
                    auth_credential: elements.authCredential.value || '',
                    vpn_type: elements.vpnType.value || ''
                };

                // Setup VPN with retries
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

                // Download config with retries
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
                elements.loading.style.display = 'none';
            }
        });
    } catch (error) {
        console.error('Form initialization error:', error);
    }
}

async function init() {
    try {
        // Check if we're on the VPN setup page before trying to initialize the form
        if (isVPNSetupPage()) {
            // Start form initialization
            initializeVPNForm().catch(error => {
                console.error('Form initialization error:', error);
            });
        } else {
            console.log('Not on VPN setup page, skipping form initialization');
        }

        // Use fetch with explicit headers and timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
        
        try {
            const response = await fetch(`${BASE_URL}/api/auth/status`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Origin': window.location.origin,
                    'Cache-Control': 'no-cache',
                    'Connection': 'close' // Force HTTP/1.1 behavior
                },
                credentials: 'include',
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const authData = await response.json();
                console.log('Auth status response:', authData);

                if (authData?.enabled && !authData?.authenticated) {
                    window.location.replace('/login.html');
                    return;
                }
            }
        } catch (error) {
            clearTimeout(timeoutId);
            console.error("Error checking authentication:", error);
            // Gracefully degrade - continue without authentication
        }
    } catch (error) {
        console.error("Critical initialization error:", error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', init);