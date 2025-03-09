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

// Function to track and display server logs
function setupLogTracker(logContainer, statusElement) {
    const logMessages = [];
    const MAX_LOGS = 50;
    let isError = false;
    let eventSource = null;
    let dotCount = 0;
    let dotsInterval;
    let lastMessage = "";
    let messageCount = 1;
    
    const logsDiv = document.createElement("div");
    logsDiv.className = "server-logs";
    logsDiv.style.backgroundColor = "#000";
    logsDiv.style.color = "#00FF00";
    logsDiv.style.padding = "10px";
    logsDiv.style.marginTop = "15px";
    logsDiv.style.marginBottom = "15px";
    logsDiv.style.fontFamily = "monospace";
    logsDiv.style.fontSize = "12px";
    logsDiv.style.maxHeight = "400px";
    logsDiv.style.overflowY = "auto";
    logsDiv.style.whiteSpace = "pre-wrap";
    logsDiv.style.borderRadius = "5px";
    
    logContainer.appendChild(logsDiv);
    
    const updateLoadingDots = () => {
        const dots = '.'.repeat(dotCount + 1);
        statusElement.textContent = `Loading${dots}`;
        dotCount = (dotCount + 1) % 3;
    };

    const addLogMessage = (message) => {
        const timestamp = new Date().toISOString();
        
        // Check if this is a repeated message
        if (message === lastMessage) {
            messageCount++;
            // Update the last message with the count
            logMessages[logMessages.length - 1] = `[${timestamp}] ${message} [${messageCount}]`;
        } else {
            // New message
            lastMessage = message;
            messageCount = 1;
            logMessages.push(`[${timestamp}] ${message}`);
            if (logMessages.length > MAX_LOGS) {
                logMessages.shift();
            }
        }
        
        logsDiv.innerHTML = logMessages.join("<br>");
        logsDiv.scrollTop = logsDiv.scrollHeight;
    };
    
    const startEventSource = () => {
        updateLoadingDots();
        dotsInterval = setInterval(updateLoadingDots, 500);
        
        // Add initial status message
        addLogMessage("Starting VPN setup process...");
        
        const token = localStorage.getItem('jwt');
        if (!token || !isValidJWT(token)) {
            throw new Error('Authentication required');
        }

        // Close any existing connection
        if (eventSource) {
            eventSource.close();
        }

        // Configure connection retry behavior
        let retryCount = 0;
        const MAX_RETRIES = 5;
        const RETRY_DELAY = 2000; // 2 seconds
        let retryTimeout = null;

        const attemptConnection = () => {
            // Clear any existing retry timeouts
            if (retryTimeout) {
                clearTimeout(retryTimeout);
                retryTimeout = null;
            }

            // Create new EventSource connection
            eventSource = new EventSource(`${BASE_URL}/api/logs?type=vpn`);

            eventSource.onopen = () => {
                console.log("Log stream connection established");
                retryCount = 0; // Reset retry count on successful connection
                isError = false;
                
                // Update status if it was showing an error
                if (statusElement.textContent.includes("Error")) {
                    statusElement.style.color = "";  // Reset to default color
                    statusElement.textContent = "Connected to log stream...";
                    
                    // Remove error controls if they exist
                    const errorControls = document.querySelector("#errorControls");
                    if (errorControls) {
                        errorControls.remove();
                    }
                }
            };

            eventSource.onmessage = (event) => {
                const logs = event.data.split('\n');
                logs.forEach(log => {
                    if (log.trim()) {
                        if (log.includes('New VPN Password:')) {
                            // Extract and display password immediately
                            const password = log.split('New VPN Password:')[1].trim();
                            currentCredentials.credential = password;
                            showPasswordInfo(password, logContainer.parentNode);
                        }
                        addLogMessage(log.trim());
                    }
                });
            };

            eventSource.onerror = (error) => {
                console.warn("EventSource error:", error);
                
                // Close the current connection
                eventSource.close();
                
                // Attempt to reconnect if we haven't exceeded max retries
                if (retryCount < MAX_RETRIES) {
                    retryCount++;
                    
                    // Update status to show we're trying to reconnect
                    statusElement.textContent = `Connection lost. Reconnecting (${retryCount}/${MAX_RETRIES})...`;
                    statusElement.style.color = "#FF9900"; // Orange for warning
                    
                    // Set timeout for next retry
                    retryTimeout = setTimeout(attemptConnection, RETRY_DELAY * retryCount);
                } else if (!isError) {
                    // We've exceeded max retries, show the error UI
                    isError = true;
                    clearInterval(dotsInterval);
                    
                    statusElement.textContent = `Error: Connection lost`;
                    statusElement.style.color = "#FF0000";
                    addLogMessage(`Error: Connection to log stream lost`);
                    
                    if (!document.querySelector("#errorControls")) {
                        const container = logContainer.parentElement;
                        const errorControls = document.createElement("div");
                        errorControls.id = "errorControls";
                        errorControls.style.marginTop = "20px";
                        errorControls.style.display = "flex";
                        errorControls.style.justifyContent = "center";
                        errorControls.style.gap = "10px";
                        
                        const retryButton = document.createElement("button");
                        retryButton.textContent = "Retry";
                        retryButton.className = "btn btn-primary";
                        retryButton.style.maxWidth = "150px";
                        retryButton.onclick = () => {
                            errorControls.remove();
                            isError = false;
                            retryCount = 0; // Reset retry count for manual retry
                            statusElement.style.color = "";  // Reset to default color
                            statusElement.textContent = "Loading...";  // Reset text
                            attemptConnection();
                        };
                        
                        const cancelButton = document.createElement("button");
                        cancelButton.textContent = "Cancel";
                        cancelButton.className = "btn btn-secondary";
                        cancelButton.style.maxWidth = "150px";
                        cancelButton.onclick = () => {
                            if (eventSource) {
                                eventSource.close();
                            }
                            document.querySelector("#setupProgress").style.display = "none";
                            document.querySelector("#vpnForm").style.display = "block";
                            logsDiv.remove();
                            errorControls.remove();
                        };
                        
                        errorControls.appendChild(retryButton);
                        errorControls.appendChild(cancelButton);
                        container.appendChild(errorControls);
                    }
                }
            };
        };
        
        // Start the connection
        attemptConnection();
    };
    
    startEventSource();
    
    return {
        complete: () => {
            if (eventSource) {
                eventSource.close();
            }
            clearInterval(dotsInterval);
            statusElement.textContent = "Setup completed successfully!";
            statusElement.style.color = "#00FF00";
            
            const errorControls = document.querySelector("#errorControls");
            if (errorControls) {
                errorControls.remove();
            }
        },
        error: (message) => {
            isError = true;
            if (eventSource) {
                eventSource.close();
            }
            clearInterval(dotsInterval);
            
            statusElement.textContent = `Error: ${message}`;
            statusElement.style.color = "#FF0000";
            addLogMessage(`Error: ${message}`);
            
            if (!document.querySelector("#errorControls")) {
                const container = logContainer.parentElement;
                const errorControls = document.createElement("div");
                errorControls.id = "errorControls";
                errorControls.style.marginTop = "20px";
                errorControls.style.display = "flex";
                errorControls.style.justifyContent = "center";
                errorControls.style.gap = "10px";
                
                const retryButton = document.createElement("button");
                retryButton.textContent = "Retry";
                retryButton.className = "btn btn-primary";
                retryButton.style.maxWidth = "150px";
                retryButton.onclick = () => {
                    errorControls.remove();
                    isError = false;
                    statusElement.style.color = "#00FF00";
                    document.querySelector("#vpnForm").dispatchEvent(new Event("submit"));
                };
                
                const cancelButton = document.createElement("button");
                cancelButton.textContent = "Cancel";
                cancelButton.className = "btn btn-secondary";
                cancelButton.style.maxWidth = "150px";
                cancelButton.onclick = () => {
                    if (eventSource) {
                        eventSource.close();
                    }
                    document.querySelector("#setupProgress").style.display = "none";
                    document.querySelector("#vpnForm").style.display = "block";
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
function generateDownloadLink(baseUrl, filename, credentials) {
    const params = new URLSearchParams({
        serverIp: credentials.serverIp,
        username: credentials.username,
        credential: credentials.credential,
        vpnType: credentials.vpnType
    });
    
    const downloadUrl = `${baseUrl}?${params.toString()}`;
    
    // Instead of returning a direct URL, return a data URL that will trigger download with proper headers
    return `javascript:downloadConfig('${downloadUrl}', '${filename}')`;
}

async function downloadConfig(url, filename) {
    try {
        const token = localStorage.getItem('jwt');
        if (!token) {
            throw new Error('Not authenticated');
        }

        // Show loading indicator
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.textContent = 'Downloading configuration...';
            errorElement.style.display = 'block';
            errorElement.className = 'info';
        }

        // Add retry logic for potential TLS handshake errors
        let response;
        const maxRetries = 3;
        
        for (let attempt = 0; attempt < maxRetries; attempt++) {
            try {
                response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/octet-stream',
                        'Cache-Control': 'no-cache'
                    },
                    credentials: 'include'
                });
                
                if (response.ok) {
                    break; // Success, exit retry loop
                }
                
                // If we got an error response but not a network error, don't retry
                if (response.status !== 0) {
                    throw new Error(`HTTP error: ${response.status} ${response.statusText}`);
                }
                
                // Wait before retrying
                console.log(`Download attempt ${attempt + 1} failed, retrying...`);
                if (errorElement) {
                    errorElement.textContent = `Download attempt ${attempt + 1} failed, retrying...`;
                }
                await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
            } catch (fetchError) {
                console.error(`Download attempt ${attempt + 1} failed:`, fetchError);
                
                // On last attempt, rethrow the error
                if (attempt === maxRetries - 1) {
                    throw fetchError;
                }
                
                // Wait before retrying
                await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
            }
        }

        if (!response || !response.ok) {
            throw new Error(`Download failed: ${response ? response.statusText : 'Connection error'}`);
        }

        // Get the blob from response
        const blob = await response.blob();
        
        if (blob.size === 0) {
            throw new Error('Downloaded file is empty');
        }
        
        // Clear any error messages
        if (errorElement) {
            errorElement.style.display = 'none';
        }
        
        // Create download link
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = filename;
        
        // Trigger download
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Cleanup
        window.URL.revokeObjectURL(downloadUrl);
    } catch (error) {
        console.error('Download failed:', error);
        
        // Display error in UI
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.textContent = 'Failed to download configuration: ' + error.message;
            errorElement.style.display = 'block';
            errorElement.className = 'error';
        }
        
        alert('Failed to download configuration: ' + error.message + '\nPlease try again or contact support.');
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
            
            // Clear any error messages
            const errorElement = document.getElementById('error-message');
            if (errorElement) {
                errorElement.style.display = 'none';
            }

            // Start log tracking with error handling
            let logTracker;
            try {
                logTracker = setupLogTracker(elements.progress, elements.statusText);
            } catch (error) {
                console.error('Failed to setup log tracker:', error);
                
                // Show error and return to form
                if (errorElement) {
                    errorElement.textContent = 'Failed to connect to log stream: ' + error.message;
                    errorElement.style.display = 'block';
                }
                elements.form.style.display = 'block';
                elements.progress.style.display = 'none';
                return;
            }

            try {
                // First verify auth status with proper headers
                const token = localStorage.getItem('jwt');
                if (!token || !isValidJWT(token)) {
                    throw new Error('JWT token missing or invalid');
                }

                // Set a 30-second timeout for the entire setup process
                const setupTimeout = setTimeout(() => {
                    throw new Error('Setup operation timed out after 30 seconds');
                }, 30000);

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

                // Intercept all responses to check for expired password
                const originalFetch = window.fetch;
                window.fetch = async function(url, options) {
                    const response = await originalFetch(url, options);
                    
                    // Check for expired password response
                    if (response.status === 403) {
                        try {
                            const clonedResponse = response.clone();
                            const data = await clonedResponse.json();
                            
                            if (data && data.status === "expired_password" && data.new_password) {
                                console.log('Intercepted expired password response:', data);
                                // Save the data to a globally accessible variable
                                window.expiredPasswordData = data;
                            }
                        } catch (e) {
                            console.error('Error checking for expired password in response:', e);
                        }
                    }
                    
                    return response;
                };

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
                
                // Clear the timeout since the request completed
                clearTimeout(setupTimeout);
                
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
                if (logTracker) {
                    logTracker.complete();
                }
                
                // Show success message and create download links
                elements.result.textContent = 'VPN setup completed successfully!';
                elements.result.className = 'success';
                elements.result.style.display = 'block';
                
                // Display new password information if available
                if (responseData && responseData.new_password) {
                    console.log('New password received, displaying in UI');
                    showPasswordInfo(responseData.new_password, elements.progress.parentNode);
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
                
                // Check for globally saved expired password data
                if (window.expiredPasswordData) {
                    console.log('Found saved expired password data:', window.expiredPasswordData);
                    
                    // Show error message but with password reset information
                    const errorElement = document.getElementById('error-message');
                    if (errorElement) {
                        errorElement.textContent = 'Password has expired. Please use the new password shown below for future connections.';
                        errorElement.style.display = 'block';
                    }
                    
                    // Display the new password
                    showPasswordInfo(window.expiredPasswordData.new_password, elements.progress.parentNode);
                    
                    // Clear the global variable
                    window.expiredPasswordData = null;
                    
                    // Return early to avoid showing the general error
                    elements.form.style.display = 'block';
                    elements.progress.style.display = 'none';
                    return;
                }
                
                // Check if this is an expired password response
                if (error.response && error.response.status === 403) {
                    try {
                        const responseData = await error.response.json();
                        if (responseData && responseData.status === "expired_password" && responseData.new_password) {
                            console.log('Detected expired password response with new password');
                            
                            // Show error message but with password reset information
                            const errorElement = document.getElementById('error-message');
                            if (errorElement) {
                                errorElement.textContent = 'Password has expired. Please use the new password shown below for future connections.';
                                errorElement.style.display = 'block';
                            }
                            
                            // Display the new password
                            showPasswordInfo(responseData.new_password, elements.progress.parentNode);
                            
                            // Return early to avoid showing the general error
                            elements.form.style.display = 'block';
                            elements.progress.style.display = 'none';
                            return;
                        }
                    } catch (jsonError) {
                        console.error('Error parsing expired password response:', jsonError);
                    }
                }
                
                // Check for fetch Response object directly
                if (error.status === 403) {
                    try {
                        const responseData = await error.json();
                        if (responseData && responseData.status === "expired_password" && responseData.new_password) {
                            console.log('Detected expired password response with new password');
                            
                            // Show error message but with password reset information
                            const errorElement = document.getElementById('error-message');
                            if (errorElement) {
                                errorElement.textContent = 'Password has expired. Please use the new password shown below for future connections.';
                                errorElement.style.display = 'block';
                            }
                            
                            // Display the new password
                            showPasswordInfo(responseData.new_password, elements.progress.parentNode);
                            
                            // Return early to avoid showing the general error
                            elements.form.style.display = 'block';
                            elements.progress.style.display = 'none';
                            return;
                        }
                    } catch (jsonError) {
                        console.error('Error parsing expired password response directly:', jsonError);
                    }
                }
                
                // Attempt to complete log tracking if it exists
                if (logTracker && logTracker.complete) {
                    try {
                        logTracker.complete();
                    } catch (logError) {
                        console.error('Error completing log tracker:', logError);
                    }
                }
                
                // Display error in the UI
                const errorElement = document.getElementById('error-message');
                if (errorElement) {
                    errorElement.textContent = 'Setup failed: ' + (error.message || 'Unknown error');
                    errorElement.style.display = 'block';
                }
                
                if (error.message?.includes('JWT token') || error.message?.includes('Authentication required')) {
                    // Auth token issue - redirect to login
                    setTimeout(() => {
                        window.location.href = '/login.html?auth_error=true';
                    }, 2000); // Delay to allow user to see the error message
                } else if (error.message?.includes('Could not connect') || 
                           error.message?.includes('Network error') ||
                           error.message?.includes('Connection lost') ||
                           error.message?.includes('timed out')) {
                    // Network connection issues
                    elements.result.textContent = 'Connection to server lost. Please try again.';
                    elements.result.className = 'error';
                    elements.result.style.display = 'block';
                    
                    // Add retry button at the result level
                    const retryButtonContainer = document.createElement('div');
                    retryButtonContainer.style.marginTop = '15px';
                    retryButtonContainer.style.display = 'flex';
                    retryButtonContainer.style.justifyContent = 'center';
                    
                    const retryButton = document.createElement('button');
                    retryButton.textContent = 'Retry Setup';
                    retryButton.className = 'btn btn-primary';
                    retryButton.onclick = () => {
                        // Reload the page to start fresh
                        window.location.reload();
                    };
                    
                    retryButtonContainer.appendChild(retryButton);
                    elements.result.appendChild(retryButtonContainer);
                } else {
                    // General error
                    elements.result.textContent = 'Setup failed: ' + (error.message || 'An unexpected error occurred');
                    elements.result.className = 'error';
                    elements.result.style.display = 'block';
                }
                
                // Show the form again
                elements.form.style.display = 'block';
                elements.progress.style.display = 'none';
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