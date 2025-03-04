// Basic HTTP retry functionality
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second base delay

// Configure base URL based on environment
const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? `http://${window.location.host}`
    : `https://${window.location.host}`;

// Setup stages and their weights for progress calculation
const SETUP_STAGES = [
    { name: "Installing packages", weight: 20 },
    { name: "Generating certificates", weight: 15 },
    { name: "Configuring VPN", weight: 35 },
    { name: "Setting up security", weight: 15 },
    { name: "Starting services", weight: 10 },
    { name: "Finalizing configuration", weight: 5 }
];

// Function to get CSRF token with retries
async function getCsrfToken(retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await fetch(`${BASE_URL}/api/csrf-token`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Origin': window.location.origin,
                    'Cache-Control': 'no-cache'
                },
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            if (!data.token) {
                throw new Error('No token in response');
            }
            return data.token;
        } catch (error) {
            console.error(`CSRF token fetch attempt ${i + 1} failed:`, error);
            if (i === retries - 1) {
                throw error;
            }
            // Wait before retrying, with exponential backoff
            await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
        }
    }
}

// Helper function for retrying failed requests
async function fetchWithRetries(url, options, retries = MAX_RETRIES) {
    for (let i = 0; i < retries; i++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // Increased timeout to 30 seconds
            
            const token = localStorage.getItem('jwt');
            const defaultHeaders = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'Origin': window.location.origin
            };

            if (token) {
                defaultHeaders['Authorization'] = `Bearer ${token}`;
            }
            
            const response = await fetch(url, {
                ...options,
                signal: controller.signal,
                headers: {
                    ...defaultHeaders,
                    ...options.headers
                },
                credentials: 'include'
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                if (response.status === 401) {
                    // Clear token and redirect on unauthorized
                    localStorage.removeItem('jwt');
                    window.location.replace('/login.html?auth_error=true');
                    throw new Error('Authentication required');
                }
                
                const errorText = await response.text();
                let errorMessage;
                try {
                    const errorJson = JSON.parse(errorText);
                    errorMessage = errorJson.error || errorText;
                } catch {
                    errorMessage = errorText;
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
    throw new Error('Max retries reached');
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

// Function to simulate progress based on stages
function simulateProgress(progressBar, statusElement) {
    let currentStage = 0;
    let currentProgress = 0;
    let stageProgress = 0;
    
    // Calculate total weight
    const totalWeight = SETUP_STAGES.reduce((sum, stage) => sum + stage.weight, 0);
    
    // Update status text and progress bar
    const updateProgress = () => {
        const stage = SETUP_STAGES[currentStage];
        statusElement.textContent = stage.name + "...";
        
        // Calculate overall progress percentage
        let previousStagesWeight = 0;
        for (let i = 0; i < currentStage; i++) {
            previousStagesWeight += SETUP_STAGES[i].weight;
        }
        
        const stageContribution = (stageProgress / 100) * stage.weight;
        currentProgress = Math.min(((previousStagesWeight + stageContribution) / totalWeight) * 100, 99);
        
        // Update progress bar
        progressBar.style.width = currentProgress.toFixed(1) + '%';
    };
    
    // Start progress simulation
    updateProgress();
    
    // Simulate progress through stages
    const interval = setInterval(() => {
        stageProgress += Math.random() * 3; // Random increment
        
        if (stageProgress >= 100) {
            currentStage++;
            stageProgress = 0;
            
            if (currentStage >= SETUP_STAGES.length) {
                clearInterval(interval);
                return;
            }
        }
        
        updateProgress();
    }, 250);
    
    return {
        complete: () => {
            clearInterval(interval);
            progressBar.style.width = '100%';
            statusElement.textContent = 'Setup completed successfully!';
        },
        error: (message) => {
            clearInterval(interval);
            statusElement.textContent = `Error: ${message}`;
            statusElement.style.color = '#d9534f';
        }
    };
}

// Function to download a file from a URL
async function downloadFile(url, filename, params) {
    try {
        // Get CSRF token for the download request
        const csrfToken = await getCsrfToken();
        if (!csrfToken) {
            throw new Error('Could not get CSRF token for download');
        }

        // Get JWT token
        const jwtToken = localStorage.getItem('jwt');

        const response = await fetchWithRetries(
            url + (params ? '?' + new URLSearchParams(params) : ''),
            {
                headers: {
                    'Accept': 'application/octet-stream',
                    'Origin': window.location.origin,
                    'X-CSRF-Token': csrfToken,
                    'Authorization': jwtToken ? `Bearer ${jwtToken}` : ''
                },
                credentials: 'include'
            }
        );

        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        return true;
    } catch (error) {
        console.error(`Error downloading ${filename}:`, error);
        return false;
    }
}

// Function to validate the JWT token's format (not its signature)
function isValidJWT(token) {
    if (!token) return false;
    
    // JWT tokens have 3 parts separated by dots
    const parts = token.split('.');
    if (parts.length !== 3) {
        console.error('Malformed JWT token: wrong number of segments');
        return false;
    }
    
    try {
        // Try to parse the payload (middle part)
        const payload = JSON.parse(atob(parts[1]));
        
        // Check expiration with a 5-minute buffer for clock skew
        if (payload.exp && Date.now() >= (payload.exp * 1000) - (5 * 60 * 1000)) {
            console.error('JWT token has expired or is about to expire');
            localStorage.removeItem('jwt');
            return false;
        }

        // Validate required claims
        if (!payload.username || !payload.sub || !payload.iss) {
            console.error('JWT token missing required claims');
            return false;
        }
        
        return true;
    } catch (e) {
        console.error('Failed to parse JWT payload:', e);
        return false;
    }
}

// Helper function to refresh authentication state
async function refreshAuthState() {
    try {
        const token = localStorage.getItem('jwt');
        if (!token || !isValidJWT(token)) {
            throw new Error('Invalid or expired token');
        }

        const response = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`,
                'Origin': window.location.origin
            },
            credentials: 'include'
        });

        const authData = await response.json();
        if (!authData?.authenticated) {
            throw new Error('Not authenticated');
        }

        return true;
    } catch (error) {
        console.error('Auth refresh failed:', error);
        localStorage.removeItem('jwt');
        window.location.replace('/login.html?auth_error=true');
        return false;
    }
}

async function initializeVPNForm() {
    try {
        // Wait for the form element first
        const form = await waitForElement('#vpnForm');
        if (!form) {
            console.log('VPN form not found on this page');
            return; // Exit early if form doesn't exist
        }
        
        // Verify authentication state before proceeding
        if (!await refreshAuthState()) {
            return;
        }

        // Only proceed if we have the form element
        const elements = {
            form: form,
            serverIp: document.querySelector('#serverIp'),
            username: document.querySelector('#username'),
            authMethod: document.querySelector('#authMethod'),
            authCredential: document.querySelector('#authCredential'),
            vpnType: document.querySelector('#vpnType'),
            setupButton: document.querySelector('#setupButton'),
            result: document.querySelector('#result') || createFallbackElement('div', 'result'),
            error: document.querySelector('#downloadError') || createFallbackElement('div', 'downloadError'),
            loading: document.querySelector('#loading') || createFallbackElement('div', 'loading'),
            progress: document.querySelector('#setupProgress'),
            progressBar: document.querySelector('#setupProgressBar'),
            statusText: document.querySelector('#setupStatus'),
            downloads: document.querySelector('#downloads'),
            downloadClientBtn: document.querySelector('#downloadClientConfig'),
            downloadServerBtn: document.querySelector('#downloadServerConfig')
        };

        // Check if critical elements are missing before proceeding
        if (!elements.serverIp || !elements.username || 
            !elements.authCredential || !elements.vpnType || !elements.authMethod) {
            console.error('Required form elements missing - cannot initialize form');
            return; // Exit early if required elements are missing
        }
        
        // Store credentials for later use with download buttons
        let currentCredentials = {
            serverIp: '',
            username: '',
            credential: '',
            vpnType: ''
        };

        // Initialize download buttons only after they're shown
        const initializeDownloadButtons = () => {
            if (elements.downloadClientBtn) {
                elements.downloadClientBtn.addEventListener('click', async () => {
                    elements.statusText.textContent = 'Downloading client configuration...';
                    await downloadFile(
                        `${BASE_URL}/api/config/download/client`,
                        currentCredentials.vpnType === 'openvpn' ? 'client.ovpn' : 'vpn_config.mobileconfig',
                        currentCredentials
                    );
                    elements.statusText.textContent = 'Client configuration downloaded';
                });
            }
            
            if (elements.downloadServerBtn) {
                elements.downloadServerBtn.addEventListener('click', async () => {
                    elements.statusText.textContent = 'Downloading server configuration...';
                    await downloadFile(
                        `${BASE_URL}/api/config/download/server`,
                        'server.conf',
                        currentCredentials
                    );
                    elements.statusText.textContent = 'Server configuration downloaded';
                });
            }
        };

        // Now safely add the event listener - form is guaranteed to exist at this point
        elements.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Verify auth state before submitting
            if (!await refreshAuthState()) {
                return;
            }

            // Hide previous results and errors
            elements.result.style.display = 'none';
            elements.error.style.display = 'none';
            elements.downloads.style.display = 'none';
            
            // Show progress tracking UI
            elements.form.style.display = 'none';
            elements.progress.style.display = 'block';
            
            // Start progress animation
            const progress = simulateProgress(elements.progressBar, elements.statusText);

            try {
                // First verify auth status with proper headers
                const token = localStorage.getItem('jwt');
                if (!token || !isValidJWT(token)) {
                    throw new Error('JWT token missing or invalid');
                }

                const authResponse = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                let authStatus;
                try {
                    authStatus = await authResponse.json();
                    console.log('Auth status before setup:', authStatus);
                } catch (jsonError) {
                    console.error('Error parsing auth status:', jsonError);
                    throw new Error('Invalid response from server');
                }

                // Check if we're authenticated
                if (!authStatus?.authenticated) {
                    console.error('Not authenticated according to auth status');
                    throw new Error('Authentication required');
                }

                // Get CSRF token
                console.log('Getting CSRF token...');
                const csrfToken = await getCsrfToken();
                if (!csrfToken) {
                    console.error('Failed to get CSRF token');
                    throw new Error('Could not get CSRF token');
                }
                console.log('Got CSRF token:', csrfToken.substring(0, 10) + '...');

                const formData = {
                    server_ip: elements.serverIp.value || '',
                    username: elements.username.value || '',
                    auth_method: elements.authMethod.value || '',
                    auth_credential: elements.authCredential.value || '',
                    vpn_type: elements.vpnType.value || ''
                };
                
                // Store credentials for download buttons
                currentCredentials = {
                    serverIp: formData.server_ip,
                    username: formData.username,
                    credential: formData.auth_credential,
                    vpnType: formData.vpn_type
                };

                // Prepare headers with both tokens
                const headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Origin': window.location.origin,
                    'X-CSRF-Token': csrfToken,
                    'Authorization': `Bearer ${token}`
                };

                console.log('Sending setup request with headers:', 
                    Object.entries(headers)
                        .map(([k, v]) => k === 'Authorization' ? 
                            `${k}: Bearer ${v.split(' ')[1].substring(0, 10)}...` : 
                            `${k}: ${v.substring(0, 10)}...`)
                        .join(', ')
                );

                // Setup VPN with retries
                const setupResponse = await fetchWithRetries(`${BASE_URL}/api/setup`, {
                    method: 'POST',
                    headers: headers,
                    credentials: 'include',
                    body: JSON.stringify(formData)
                });

                // Complete the progress bar animation
                progress.complete();
                
                // Show success message and download buttons
                elements.result.textContent = 'VPN setup completed successfully!';
                elements.result.className = 'success';
                elements.result.style.display = 'block';
                elements.downloads.style.display = 'flex';

                // Initialize download buttons after showing them
                initializeDownloadButtons();
            } catch (error) {
                console.error('Setup error:', error);
                progress.error(error.message);
                
                if (error.message?.includes('JWT token')) {
                    // Auth token issue - redirect to login
                    window.location.href = '/login.html?auth_error=true';
                } else if (error.message?.includes('Could not connect') || error.message?.includes('Network error')) {
                    window.location.href = '/error/backend-down.html';
                } else {
                    elements.error.textContent = error.message || 'An unexpected error occurred';
                    elements.error.style.display = 'block';
                    elements.form.style.display = 'block';  // Show the form again
                }
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
            if (document.readyState === "complete" || document.readyState === "interactive") {
                initializeVPNForm().catch(error => {
                    console.error('Form initialization error:', error);
                    if (error.message?.includes('Authentication required') || 
                        error.message?.includes('JWT token') || 
                        error.message?.includes('token expired')) {
                        window.location.replace('/login.html?auth_error=true');
                    }
                });
            } else {
                document.addEventListener('DOMContentLoaded', () => {
                    initializeVPNForm().catch(error => {
                        console.error('Form initialization error:', error);
                        if (error.message?.includes('Authentication required') || 
                            error.message?.includes('JWT token') || 
                            error.message?.includes('token expired')) {
                            window.location.replace('/login.html?auth_error=true');
                        }
                    });
                });
            }
        } else {
            console.log('Not on VPN setup page, skipping form initialization');
        }

        // Always verify auth state on page load
        const authState = await refreshAuthState();
        if (!authState && window.location.pathname !== '/login.html') {
            window.location.replace('/login.html?auth_error=true');
            return;
        }

        try {
            const token = localStorage.getItem('jwt');
            const headers = {
                'Accept': 'application/json',
                'Origin': window.location.origin,
                'Cache-Control': 'no-cache'
            };
            
            if (token) {
                if (!isValidJWT(token)) {
                    // If token is invalid, clear it and redirect
                    localStorage.removeItem('jwt');
                    if (window.location.pathname !== '/login.html') {
                        window.location.replace('/login.html?auth_error=true');
                    }
                    return;
                }
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            const response = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
                method: 'GET',
                headers: headers,
                credentials: 'include'
            });
            
            let authData = await response.json();
            console.log('Auth status response:', authData);

            if (authData?.enabled && !authData?.authenticated) {
                // Clear invalid token and redirect
                localStorage.removeItem('jwt');
                if (window.location.pathname !== '/login.html') {
                    window.location.replace('/login.html');
                }
                return;
            }

        } catch (error) {
            console.error("Error checking authentication:", error);
            // On network error, let the user continue - they'll be redirected if auth is required
        }
    } catch (error) {
        console.error("Critical initialization error:", error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', init);