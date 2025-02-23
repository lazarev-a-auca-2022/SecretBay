// Authentication and CSRF token management
let csrfToken = null;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

// Helper function to delay execution
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Helper function to check if an element exists
function getElementByIdSafe(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.error(`Element with id ${id} not found`);
    }
    return element;
}

// Helper function to initialize form
function initializeVPNForm() {
    const vpnForm = document.getElementById('vpnForm');
    if (!vpnForm) {
        console.debug('VPN form not found on this page, skipping initialization');
        return;
    }
    
    const loadingDiv = getElementByIdSafe('loading');
    const resultDiv = getElementByIdSafe('result');
    const errorDiv = getElementByIdSafe('downloadError');

    if (!loadingDiv || !resultDiv || !errorDiv) {
        console.error('Required DOM elements not found');
        return;
    }

    vpnForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loadingDiv.style.display = 'block';
        resultDiv.style.display = 'none';
        errorDiv.style.display = 'none';

        try {
            // ... rest of the form submission code ...
            const response = await fetch('/api/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    server_ip: getElementByIdSafe('serverIp').value,
                    username: getElementByIdSafe('username').value,
                    auth_method: getElementByIdSafe('authMethod').value,
                    auth_credential: getElementByIdSafe('authCredential').value,
                    vpn_type: getElementByIdSafe('vpnType').value
                })
            });

            if (!response.ok) {
                throw new Error('Failed to setup VPN');
            }

            const data = await response.json();
            resultDiv.textContent = 'VPN setup successful!';
            resultDiv.style.display = 'block';
        } catch (error) {
            console.error('Setup error:', error);
            errorDiv.textContent = error.message || 'An unexpected error occurred';
            errorDiv.style.display = 'block';
        } finally {
            loadingDiv.style.display = 'none';
        }
    });
}

// Main initialization
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // First check if auth is enabled
        const authResponse = await fetch('/api/auth/status', {
            headers: {
                'Accept': 'application/json',
                'Cache-Control': 'no-cache'
            }
        });

        if (!authResponse.ok) {
            throw new Error('Failed to check auth status');
        }

        const authStatus = await authResponse.json().catch(() => {
            throw new Error('Invalid JSON response');
        });
        
        // If auth is disabled, initialize form directly
        if (!authStatus.enabled) {
            initializeVPNForm();
            return;
        }

        // Otherwise check authentication
        const token = localStorage.getItem('jwt');
        if (!token) {
            window.location.href = '/login.html';
            return;
        }

        // Verify token
        const verifyResponse = await fetch('/api/vpn/status', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            }
        });

        if (!verifyResponse.ok) {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html';
            return;
        }

        // If we get here, auth is good, initialize form
        initializeVPNForm();

    } catch (error) {
        console.error('Initialization error:', error);
        const errorDiv = getElementByIdSafe('downloadError');
        if (errorDiv) {
            errorDiv.textContent = 'Failed to initialize application. Please try refreshing the page.';
            errorDiv.style.display = 'block';
        }
    }
});