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
        if (!response.ok || response.status === 401 || response.status === 403) {
            localStorage.removeItem('jwt');
            window.location.href = '/login.html';
            return;
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        localStorage.removeItem('jwt');
        window.location.href = '/login.html';
    }
});

// Function to get JWT token
async function getJWTToken() {
    let token = localStorage.getItem('jwt');
    if (!token) {
        try {
            const response = await fetch('/api/auth/token', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
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

// Handle config download
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
        let token = await getJWTToken();
        if (!token) throw new Error('Authentication failed');
        
        const response = await fetch(`/api/config/download?server_ip=${serverIp}&username=${username}&credential=${encodeURIComponent(credential)}`, {
            headers: {
                'Authorization': `Bearer ${token}`
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
        a.download = "openvpn_config.ovpn";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        errorDiv.textContent = error.message || "No VPN detected on the remote host";
        errorDiv.style.display = "block";
    }
});

// Handle form submission
document.getElementById('vpnForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const resultDiv = document.getElementById('result');
    resultDiv.style.display = 'none';

    try {
        let token = await getJWTToken();
        if (!token || !(await isTokenValid(token))) {
            localStorage.removeItem('jwt');
            token = await getJWTToken();
            if (!token) {
                throw new Error('Could not authenticate. Please try again.');
            }
        }

        let response = await fetch('/api/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                server_ip: document.getElementById('serverIp').value,
                username: document.getElementById('username').value,
                auth_method: document.getElementById('authMethod').value,
                auth_credential: document.getElementById('authCredential').value,
                vpn_type: document.getElementById('vpnType').value
            })
        });

        if (response.status === 401) {
            localStorage.removeItem('jwt');
            token = await getJWTToken();
            if (token) {
                response = await fetch('/api/setup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        server_ip: document.getElementById('serverIp').value,
                        username: document.getElementById('username').value,
                        auth_method: document.getElementById('authMethod').value,
                        auth_credential: document.getElementById('authCredential').value,
                        vpn_type: document.getElementById('vpnType').value
                    })
                });
            }
        }

        const data = await response.json();
        if (response.ok) {
            resultDiv.textContent = `VPN setup successful! Config path: ${data.vpn_config}\nNew root password: ${data.new_password}`;
            resultDiv.className = 'success';
        } else {
            resultDiv.textContent = `Error: ${data.error || 'Unknown error occurred'}`;
            resultDiv.className = 'error';
        }
        resultDiv.style.display = 'block';
    } catch (error) {
        resultDiv.textContent = `Error: ${error.message}`;
        resultDiv.className = 'error';
        resultDiv.style.display = 'block';
    }
});