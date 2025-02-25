// Authentication and CSRF token management (temporarily disabled)
let csrfToken = 'disabled';  // Hardcoded token while auth is disabled
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000;

// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

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
            // Setup VPN (auth checks removed)
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
            }).catch(error => {
                console.error('Failed to setup VPN:', error);
                window.location.href = '/error/backend-down.html';
                return null;
            });

            if (!setupResponse) return;

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

            // Download config (auth checks removed)
            const serverIp = document.getElementById('serverIp')?.value || '';
            const username = document.getElementById('username')?.value || '';
            const credential = document.getElementById('authCredential')?.value || '';

            const downloadResponse = await fetchWithRetries(`${BASE_URL}/api/config/download?server_ip=${encodeURIComponent(serverIp)}&username=${encodeURIComponent(username)}&credential=${encodeURIComponent(credential)}`, {
                headers: {
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
}

// Initialize immediately without auth checks
document.addEventListener('DOMContentLoaded', () => {
    initializeVPNForm();
});