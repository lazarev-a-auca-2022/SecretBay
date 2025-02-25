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
            return response;
        } catch (error) {
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * Math.pow(2, i)));
        }
    }
}

// Initialize form handling
function initializeVPNForm() {
    const vpnForm = document.getElementById('vpnForm');
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('downloadError');

    // Only proceed if we're on the VPN setup page and all elements exist
    if (!vpnForm || !resultDiv || !errorDiv) {
        return;
    }

    vpnForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultDiv.style.display = 'none';
        errorDiv.style.display = 'none';

        try {
            // Setup VPN
            const setupResponse = await fetchWithRetries(`${BASE_URL}/api/setup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
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
            });

            if (!setupResponse.ok) {
                const setupData = await setupResponse.json();
                throw new Error(setupData.error || 'Failed to setup VPN');
            }

            resultDiv.textContent = 'VPN setup successful! Downloading configuration...';
            resultDiv.style.color = 'green';
            resultDiv.style.display = 'block';

            // Download config
            const serverIp = document.getElementById('serverIp')?.value || '';
            const username = document.getElementById('username')?.value || '';
            const credential = document.getElementById('authCredential')?.value || '';

            const downloadResponse = await fetchWithRetries(`${BASE_URL}/api/config/download?server_ip=${encodeURIComponent(serverIp)}&username=${encodeURIComponent(username)}&credential=${encodeURIComponent(credential)}`, {
                headers: {
                    'Accept': 'application/octet-stream',
                    'Origin': window.location.origin
                },
                credentials: 'include'
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
}

// Initialize form on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeVPNForm();
});