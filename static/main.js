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

// Function to track and display server logs instead of a progress bar
function setupLogTracker(logContainer, statusElement) {
    const logMessages = [];
    const MAX_LOGS = 5; // Number of log messages to display
    let isError = false;
    let pollInterval;
    
    // Create a styled log container
    const logsDiv = document.createElement('div');
    logsDiv.className = 'server-logs';
    logsDiv.style.backgroundColor = '#f8f9fa';
    logsDiv.style.border = '1px solid #dee2e6';
    logsDiv.style.borderRadius = '4px';
    logsDiv.style.padding = '10px';
    logsDiv.style.marginTop = '15px';
    logsDiv.style.marginBottom = '15px';
    logsDiv.style.fontFamily = 'monospace';
    logsDiv.style.fontSize = '12px';
    logsDiv.style.maxHeight = '200px';
    logsDiv.style.overflowY = 'auto';
    logsDiv.style.whiteSpace = 'pre-wrap';
    logContainer.appendChild(logsDiv);
    
    // Function to add a log message
    const addLogMessage = (message) => {
        const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
        logMessages.push(`[${timestamp}] ${message}`);
        
        // Keep only the last MAX_LOGS messages
        while (logMessages.length > MAX_LOGS) {
            logMessages.shift();
        }
        
        // Update the display
        logsDiv.innerHTML = logMessages.join('<br>');
        
        // Auto-scroll to bottom
        logsDiv.scrollTop = logsDiv.scrollHeight;
    };
    
    // Initial message
    addLogMessage('Starting VPN setup process...');
    
    // Start polling for logs
    const startPolling = () => {
        pollInterval = setInterval(async () => {
            try {
                const token = localStorage.getItem('jwt');
                if (!token || !isValidJWT(token)) {
                    clearInterval(pollInterval);
                    addLogMessage('Auth token invalid or expired. Please login again.');
                    return;
                }
                
                const response = await fetch(`${BASE_URL}/api/logs?limit=5`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json',
                        'Cache-Control': 'no-cache'
                    }
                });
                
                if (!response.ok) {
                    if (response.status === 404) {
                        // Logs endpoint might not exist yet, use predefined messages
                        addLogMessage('Setting up VPN server components...');
                    } else {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return;
                }
                
                const logs = await response.json();
                
                if (logs && logs.messages && Array.isArray(logs.messages)) {
                    // Clear existing logs and add new ones
                    logMessages.length = 0;
                    logs.messages.forEach(log => {
                        logMessages.push(log);
                    });
                    // Update UI
                    logsDiv.innerHTML = logMessages.join('<br>');
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                }
                
                // Check for errors in logs
                const hasErrorInLogs = logs?.messages?.some(msg => 
                    msg.includes('Error') || 
                    msg.includes('Failed') || 
                    msg.includes('failed')
                );
                
                if (hasErrorInLogs && !isError) {
                    statusElement.textContent = 'Error detected in logs';
                    statusElement.style.color = '#d9534f';
                }
                
            } catch (error) {
                console.error('Error fetching logs:', error);
                addLogMessage(`Error fetching logs: ${error.message}`);
            }
        }, 3000); // Poll every 3 seconds
    };
    
    // Start polling immediately
    startPolling();
    
    return {
        addLog: addLogMessage,
        complete: () => {
            clearInterval(pollInterval);
            statusElement.textContent = 'Setup completed successfully!';
            statusElement.style.color = '#28a745';
            addLogMessage('VPN setup completed successfully!');
            
            // Remove any error controls that might be present
            const errorControls = document.querySelector('#errorControls');
            if (errorControls) {
                errorControls.remove();
            }
        },
        error: (message) => {
            isError = true;
            clearInterval(pollInterval); // Stop polling on error
            
            // Update status and logs
            statusElement.textContent = `Error: ${message}`;
            statusElement.style.color = '#d9534f';
            addLogMessage(`ERROR: ${message}`);
            
            // Create retry/cancel buttons if they don't already exist
            if (!document.querySelector('#errorControls')) {
                const container = logContainer.parentElement;
                
                const errorControls = document.createElement('div');
                errorControls.id = 'errorControls';
                errorControls.style.marginTop = '20px';
                errorControls.style.display = 'flex';
                errorControls.style.justifyContent = 'center';
                errorControls.style.gap = '10px';
                
                const retryButton = document.createElement('button');
                retryButton.textContent = 'Retry';
                retryButton.className = 'btn btn-primary';
                retryButton.style.maxWidth = '150px';
                retryButton.onclick = () => {
                    // Remove error controls and error state
                    errorControls.remove();
                    isError = false;
                    statusElement.style.color = '';
                    
                    // Resubmit the form
                    document.querySelector('#vpnForm').dispatchEvent(new Event('submit'));
                };
                
                const cancelButton = document.createElement('button');
                cancelButton.textContent = 'Cancel';
                cancelButton.className = 'btn btn-secondary';
                cancelButton.style.maxWidth = '150px';
                cancelButton.onclick = () => {
                    // Stop polling
                    clearInterval(pollInterval);
                    
                    // Show the form again
                    document.querySelector('#setupProgress').style.display = 'none';
                    document.querySelector('#vpnForm').style.display = 'block';
                    
                    // Remove log display and error controls
                    logsDiv.remove();
                    errorControls.remove();
                };
                
                errorControls.appendChild(retryButton);
                errorControls.appendChild(cancelButton);
                container.appendChild(errorControls);
            }
        }
    };
}

// Function to display password information in the UI
function showPasswordInfo(password, container) {
    // Create a password display section
    const passwordSection = document.createElement('div');
    passwordSection.className = 'password-section alert alert-info';
    passwordSection.style.marginBottom = '20px';
    passwordSection.style.marginTop = '20px';
    
    const passwordTitle = document.createElement('h4');
    passwordTitle.textContent = 'New VPN Password';
    
    const passwordDisplay = document.createElement('div');
    passwordDisplay.className = 'password-display';
    passwordDisplay.style.position = 'relative';
    passwordDisplay.style.marginBottom = '10px';
    
    const passwordField = document.createElement('input');
    passwordField.type = 'text';
    passwordField.readOnly = true;
    passwordField.value = password;
    passwordField.className = 'form-control';
    
    const copyButton = document.createElement('button');
    copyButton.textContent = 'Copy';
    copyButton.className = 'btn btn-sm btn-secondary';
    copyButton.style.position = 'absolute';
    copyButton.style.right = '10px';
    copyButton.style.top = '4px';
    copyButton.onclick = () => {
        passwordField.select();
        document.execCommand('copy');
        copyButton.textContent = 'Copied!';
        setTimeout(() => {
            copyButton.textContent = 'Copy';
        }, 2000);
    };
    
    const passwordNote = document.createElement('p');
    passwordNote.innerHTML = '<strong>Important:</strong> Please save this password safely. It is required for server administration.';
    
    passwordDisplay.appendChild(passwordField);
    passwordDisplay.appendChild(copyButton);
    
    passwordSection.appendChild(passwordTitle);
    passwordSection.appendChild(passwordDisplay);
    passwordSection.appendChild(passwordNote);
    
    // Insert the password section at the top of the container
    if (container.firstChild) {
        container.insertBefore(passwordSection, container.firstChild);
    } else {
        container.appendChild(passwordSection);
    }
}

// Function to generate download links instead of directly downloading files
function generateDownloadLink(url, filename, params) {
    const token = localStorage.getItem('jwt');
    if (!token || !isValidJWT(token)) {
        throw new Error('Authentication required');
    }

    const queryParams = new URLSearchParams({
        serverIp: params.serverIp,
        username: params.username,
        credential: params.credential,
        vpnType: params.vpnType
    }).toString();

    // Return the full URL with query parameters
    return `${url}?${queryParams}`;
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
                'Origin': window.location.origin,
                'Cache-Control': 'no-cache'
            },
            credentials: 'include'
        });

        const authData = await response.json();
        if (!authData?.enabled) {
            return true; // Auth is disabled, consider authenticated
        }
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
            downloadLinks: document.querySelector('#downloadLinks') || createFallbackElement('div', 'downloadLinks')
        };

        // Check if critical elements are missing before proceeding
        if (!elements.serverIp || !elements.username || 
            !elements.authCredential || !elements.vpnType || !elements.authMethod) {
            console.error('Required form elements missing - cannot initialize form');
            return; // Exit early if required elements are missing
        }
        
        // Store credentials for later use with download links
        let currentCredentials = {
            serverIp: '',
            username: '',
            credential: '',
            vpnType: ''
        };

        // Function to create download links
        const createDownloadLinks = () => {
            try {
                // Clear existing links
                elements.downloadLinks.innerHTML = '';
                
                // Create client config link
                const clientFilename = currentCredentials.vpnType === 'openvpn' ? 'client.ovpn' : 'vpn_config.mobileconfig';
                const clientUrl = generateDownloadLink(
                    `${BASE_URL}/api/config/download/client`,
                    clientFilename,
                    currentCredentials
                );
                
                // Create server config link
                const serverFilename = currentCredentials.vpnType === 'openvpn' ? 'server.conf' : 'ipsec.conf';
                const serverUrl = generateDownloadLink(
                    `${BASE_URL}/api/config/download/server`,
                    serverFilename,
                    currentCredentials
                );
                
                // Add links to the container
                const clientLink = document.createElement('a');
                clientLink.href = clientUrl;
                clientLink.className = 'download-link';
                clientLink.innerHTML = `<i class="fa fa-download"></i> Download Client Config (${clientFilename})`;
                clientLink.setAttribute('download', clientFilename);
                
                const serverLink = document.createElement('a');
                serverLink.href = serverUrl;
                serverLink.className = 'download-link';
                serverLink.innerHTML = `<i class="fa fa-download"></i> Download Server Config (${serverFilename})`;
                serverLink.setAttribute('download', serverFilename);
                
                elements.downloadLinks.appendChild(clientLink);
                elements.downloadLinks.appendChild(document.createElement('br'));
                elements.downloadLinks.appendChild(serverLink);
                
                // Show the container
                elements.downloadLinks.style.display = 'block';
            } catch (error) {
                console.error('Error creating download links:', error);
                elements.error.textContent = 'Failed to generate download links: ' + error.message;
                elements.error.style.display = 'block';
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
            elements.downloadLinks.style.display = 'none';
            
            // Remove any existing password section
            const existingPasswordSection = document.querySelector('.password-section');
            if (existingPasswordSection) {
                existingPasswordSection.remove();
            }
            
            // Show progress tracking UI
            elements.form.style.display = 'none';
            elements.progress.style.display = 'block';
            
            // Start log tracking
            const logTracker = setupLogTracker(elements.progress, elements.statusText);

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
                
                // Store credentials for download links
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
                
                // Parse response to get the new password
                let responseData;
                try {
                    responseData = await setupResponse.json();
                    console.log('Setup response received with status:', setupResponse.status);
                } catch (error) {
                    console.error('Failed to parse response JSON:', error);
                    responseData = {};
                }

                // Complete the log tracking
                logTracker.complete();
                
                // Show success message and create download links
                elements.result.textContent = 'VPN setup completed successfully!';
                elements.result.className = 'success';
                elements.result.style.display = 'block';
                
                // Display new password information if available
                if (responseData && responseData.newPassword) {
                    console.log('New password received, displaying in UI');
                    showPasswordInfo(responseData.newPassword, elements.progress.parentNode);
                } else {
                    console.log('No password received in response');
                }
                
                // Generate and show download links
                createDownloadLinks();
                
                // Hide the old download buttons if they exist
                if (elements.downloads) {
                    elements.downloads.style.display = 'none';
                }
                
            } catch (error) {
                console.error('Setup error:', error);
                
                if (error.message?.includes('JWT token')) {
                    // Auth token issue - redirect to login
                    window.location.href = '/login.html?auth_error=true';
                } else if (error.message?.includes('Could not connect') || error.message?.includes('Network error')) {
                    logTracker.error('Connection to the backend server failed. Please try again later.');
                    // Don't redirect immediately to allow the user to see the error and retry
                    // The retry button will attempt the same operation again
                } else {
                    // Call the enhanced error handler to keep the log tracking running
                    // and show retry/cancel buttons
                    logTracker.error(error.message || 'An unexpected error occurred');
                    
                    // We keep the error message visible, but don't show the form again
                    // since we now have retry/cancel buttons
                    elements.error.textContent = error.message || 'An unexpected error occurred';
                    elements.error.style.display = 'block';
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