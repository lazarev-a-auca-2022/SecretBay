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

// Helper function for retrying failed requests
async function fetchWithRetries(url, options, retries = MAX_RETRIES) {
    for (let i = 0; i < retries; i++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // Increased timeout to 30 seconds
            
            const response = await fetch(url, {
                ...options,
                signal: controller.signal,
                headers: {
                    ...options.headers,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache'
                },
                credentials: 'include'
            });
            
            clearTimeout(timeoutId);
            
            // Check for specific status codes that might be successful despite not being 200
            if (!response.ok && response.status !== 204) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
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
        const response = await fetchWithRetries(
            url + (params ? '?' + new URLSearchParams(params) : ''),
            {
                headers: {
                    'Accept': 'application/octet-stream',
                    'Origin': window.location.origin
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

async function initializeVPNForm() {
    try {
        // Wait for the form element first
        const form = await waitForElement('#vpnForm');
        if (!form) {
            console.log('VPN form not found on this page');
            return; // Exit early if form doesn't exist
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
                // First verify auth status
                const authResponse = await fetchWithRetries(`${BASE_URL}/api/auth/status`, {
                    method: 'GET',
                    credentials: 'include'
                });

                let authStatus;
                try {
                    authStatus = await authResponse.json();
                } catch (jsonError) {
                    console.error('Error parsing auth status:', jsonError);
                    throw new Error('Invalid response from server');
                }

                if (!authStatus?.authenticated) {
                    throw new Error('Authentication required');
                }

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
                
                if (error.message?.includes('Could not connect') || error.message?.includes('Network error')) {
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
            // Wait for DOM to be fully loaded and ready
            if (document.readyState === "complete" || document.readyState === "interactive") {
                initializeVPNForm().catch(error => {
                    console.error('Form initialization error:', error);
                });
            } else {
                document.addEventListener('DOMContentLoaded', () => {
                    initializeVPNForm().catch(error => {
                        console.error('Form initialization error:', error);
                    });
                });
            }
        } else {
            console.log('Not on VPN setup page, skipping form initialization');
        }

        try {
            // Use fetch with explicit headers and timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
            
            const token = localStorage.getItem('jwt');
            const headers = {
                'Accept': 'application/json',
                'Origin': window.location.origin,
                'Cache-Control': 'no-cache'
            };
            
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            const response = await fetch(`${BASE_URL}/api/auth/status`, {
                method: 'GET',
                headers: headers,
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