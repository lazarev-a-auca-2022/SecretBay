// Authentication check on page load
window.addEventListener('load', async () => {
    const token = localStorage.getItem('jwt');
    if (!token) {
        window.location.href = '/login.html';
        return;
    }
    
    try {
        const response = await fetch('/api/vpn/status', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html?auth_error=true';
            return;
        }
        
        // For other types of errors, don't redirect
        if (!response.ok) {
            console.error('Error checking authentication:', response.status);
            return;
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // Only redirect on auth errors, not network errors
        if (error.name === 'AuthenticationError') {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html?auth_error=true';
        }
    }
});

// Authentication and CSRF token management
let csrfToken = null;

async function getCsrfToken() {
    try {
        const response = await fetch('/api/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to get CSRF token');
        }
        const data = await response.json();
        csrfToken = data.token;
        return csrfToken;
    } catch (error) {
        console.error('Error getting CSRF token:', error);
        return null;
    }
}

// Function to get JWT token with CSRF support
async function getJWTToken() {
    let token = localStorage.getItem('jwt');
    if (!token) {
        try {
            // Get CSRF token first
            const csrfToken = await getCsrfToken();
            if (!csrfToken) {
                throw new Error('Failed to get CSRF token');
            }

            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });
            
            if (!response.ok) {
                throw new Error('Authentication failed');
            }
            
            const data = await response.json();
            token = data.token;
            localStorage.setItem('jwt', token);
        } catch (error) {
            console.error('Error getting JWT token:', error);
            return null;
        }
    }
    return token;
}

// Function to check if token is valid
async function isTokenValid(token) {
    try {
        const response = await fetch('/api/vpn/status', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        return response.status === 200;
    } catch (error) {
        return false;
    }
}

// Handle config download with CSRF protection
document.getElementById('downloadConfigBtn').addEventListener('click', async () => {
    const errorDiv = document.getElementById('downloadError');
    errorDiv.style.display = 'none';

    const serverIp = document.getElementById('serverIp').value;
    const username = document.getElementById('username').value;
    const credential = document.getElementById('authCredential').value;

    if (!serverIp || !credential) {
        errorDiv.textContent = "Please specify the server IP and credential.";
        errorDiv.style.display = "block";
        return;
    }
    
    try {
        // Get fresh CSRF token for download
        const csrfToken = await getCsrfToken();
        if (!csrfToken) {
            throw new Error('Could not get CSRF token');
        }

        let token = await getJWTToken();
        if (!token) throw new Error('Authentication failed');
        
        const response = await fetch(`/api/config/download?server_ip=${serverIp}&username=${username}&credential=${encodeURIComponent(credential)}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-CSRF-Token': csrfToken
            }
        });
        
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(errText);
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = "vpn_config";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        errorDiv.textContent = error.message || "Failed to download configuration";
        errorDiv.style.display = "block";
    }
});

// Handle form submission with CSRF protection
document.getElementById('vpnForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'none';

    try {
        // Get fresh CSRF token
        const csrfToken = await getCsrfToken();
        if (!csrfToken) {
            throw new Error('Could not get CSRF token');
        }

        let token = await getJWTToken();
        if (!token || !(await isTokenValid(token))) {
            localStorage.removeItem('jwt');
            token = await getJWTToken();
            if (!token) {
                throw new Error('Could not authenticate. Please try again.');
            }
        }

        const response = await fetch('/api/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({
                server_ip: document.getElementById('serverIp').value,
                username: document.getElementById('username').value,
                auth_method: document.getElementById('authMethod').value,
                auth_credential: document.getElementById('authCredential').value,
                vpn_type: document.getElementById('vpnType').value
            })
        });

        const data = await response.json();
        if (response.ok) {
            resultDiv.textContent = `VPN setup successful!\nConfig path: ${data.vpn_config}\nNew root password: ${data.new_password}`;
            if (data.backup_path) {
                resultDiv.textContent += `\nBackup created at: ${data.backup_path}`;
            }
            resultDiv.style.color = 'green';
        } else {
            throw new Error(data.error || 'Failed to setup VPN');
        }
    } catch (error) {
        resultDiv.textContent = `Error: ${error.message}`;
        resultDiv.style.color = 'red';
    }
    resultDiv.style.display = 'block';
});