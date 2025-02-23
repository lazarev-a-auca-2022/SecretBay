// Authentication and CSRF token management
let csrfToken = null;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

// Helper function to delay execution
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Helper function to initialize form
function initializeVPNForm() {
    const vpnForm = document.getElementById('vpnForm');
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('downloadError');

    if (!vpnForm || !loadingDiv || !resultDiv || !errorDiv) {
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
                    server_ip: document.getElementById('serverIp').value,
                    username: document.getElementById('username').value,
                    auth_method: document.getElementById('authMethod').value,
                    auth_credential: document.getElementById('authCredential').value,
                    vpn_type: document.getElementById('vpnType').value
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

        const authStatus = await authResponse.json();
        
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
        const errorDiv = document.getElementById('downloadError');
        if (errorDiv) {
            errorDiv.textContent = 'Failed to initialize application. Please try refreshing the page.';
            errorDiv.style.display = 'block';
        }
    }
});