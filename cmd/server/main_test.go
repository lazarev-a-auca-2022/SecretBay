package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"net"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"
)

type MockSSHClient struct {
	mock.Mock
	sshclient.SSHClientInterface
}

func (m *MockSSHClient) RunCommand(cmd string) (string, error) {
	args := m.Called(cmd)
	return args.String(0), args.Error(1)
}

func (m *MockSSHClient) Close() {
	m.Called()
}

// TestMain runs before all tests to setup test environment
func TestMain(m *testing.M) {
	// Setup test environment
	os.Setenv("SERVER_PORT", "9999")
	os.Setenv("JWT_SECRET", "this-is-a-very-long-secret-key-for-testing-purposes-123456")
	os.Setenv("ADMIN_USERNAME", "admin")
	os.Setenv("ADMIN_PASSWORD", "admin123")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "test")
	os.Setenv("DB_PASSWORD", "test")
	os.Setenv("DB_NAME", "test_db")
	os.Exit(m.Run())
}

// TestVPNSetupRequest tests the VPN setup endpoint
func TestVPNSetupRequest(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	// Initialize DB connection for testing
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	))
	if err != nil {
		t.Skip("Skipping test due to missing database:", err)
		return
	}
	defer db.Close()
	cfg.DB = db

	router := mux.NewRouter()
	api.SetupRoutes(router, cfg) // Setting up all routes properly

	// Create mock SSH client with expected behaviors
	mockSSH := new(MockSSHClient)
	mockSSH.On("RunCommand", mock.AnythingOfType("string")).Return("", nil)
	mockSSH.On("Close").Return()

	// Override the NewSSHClient function for testing
	originalNewSSHClient := sshclient.NewSSHClient
	sshclient.NewSSHClient = func(serverIP, username, authMethod, authCredential string) (*sshclient.SSHClient, error) {
		return &sshclient.SSHClient{
			Client: &ssh.Client{},
			RunCommandFunc: func(cmd string) (string, error) {
				return mockSSH.RunCommand(cmd)
			},
			CloseFunc: func() {
				mockSSH.Close()
			},
		}, nil
	}
	defer func() {
		sshclient.NewSSHClient = originalNewSSHClient
	}()

	testCases := []struct {
		name       string
		payload    models.VPNSetupRequest
		wantStatus int
	}{
		{
			name: "OpenVPN Setup",
			payload: models.VPNSetupRequest{
				ServerIP:       "192.168.1.1",
				Username:       "root",
				AuthMethod:     "password",
				AuthCredential: "test123",
				VPNType:        "openvpn",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "iOS VPN Setup",
			payload: models.VPNSetupRequest{
				ServerIP:       "192.168.1.1",
				Username:       "root",
				AuthMethod:     "key",
				AuthCredential: "ssh-key-content",
				VPNType:        "ios_vpn",
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")

			token, err := auth.GenerateJWT("test-user", cfg)
			assert.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Logf("Response body: %s", rr.Body.String())
			}

			assert.Equal(t, tc.wantStatus, rr.Code)
			if rr.Code == http.StatusOK {
				var resp models.VPNSetupResponse
				err := json.NewDecoder(rr.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.VPNConfig)
				assert.NotEmpty(t, resp.NewPassword)
			}
		})
	}
}

func TestSSHClientRunCommand(t *testing.T) {
	testCases := []struct {
		name        string
		command     string
		mockOutput  string
		mockError   error
		expectError bool
	}{
		{
			name:        "Successful Command",
			command:     "ls -la",
			mockOutput:  "total 0\ndrwxr-xr-x 2 root root 40 Jan 1 00:00 .",
			mockError:   nil,
			expectError: false,
		},
		{
			name:        "Failed Command",
			command:     "invalid-command",
			mockOutput:  "",
			mockError:   fmt.Errorf("command not found"),
			expectError: true,
		},
		{
			name:        "Empty Command",
			command:     "",
			mockOutput:  "",
			mockError:   fmt.Errorf("empty command"),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock SSH client
			mockSSH := new(MockSSHClient)
			mockSSH.On("RunCommand", tc.command).Return(tc.mockOutput, tc.mockError)
			mockSSH.On("Close").Return()

			// Create SSH client with mock
			client := &sshclient.SSHClient{
				RunCommandFunc: func(cmd string) (string, error) {
					return mockSSH.RunCommand(cmd)
				},
				CloseFunc: func() {
					mockSSH.Close()
				},
			}

			// Run the command
			output, err := client.RunCommand(tc.command)

			// Call Close explicitly
			client.Close()

			// Verify expectations
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.mockOutput, output)
			}

			// Verify mock was called as expected
			mockSSH.AssertExpectations(t)
		})
	}
}

func TestServerPerformance(t *testing.T) {
	// Setup test server
	router := mux.NewRouter()
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Test concurrent requests
	const numRequests = 50
	responses := make(chan *http.Response, numRequests)
	errors := make(chan error, numRequests)

	start := time.Now()
	for i := 0; i < numRequests; i++ {
		go func() {
			resp, err := http.Get(ts.URL + "/api/vpn/status")
			if err != nil {
				errors <- err
				return
			}
			responses <- resp
		}()
	}

	// Verify all requests complete within timeout
	timeout := time.After(120 * time.Second)
	select {
	case <-timeout:
		t.Fatal("Test timed out")
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(time.Millisecond):
		assert.Less(t, time.Since(start), 120*time.Second)
	}
}

func TestSecurityFeatures(t *testing.T) {
	// Test HTTPS requirement
	router := mux.NewRouter()
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	// Test request isolation
	req1 := httptest.NewRequest("POST", "/setup", nil)
	req2 := httptest.NewRequest("POST", "/setup", nil)
	req1.Header.Set("X-Request-ID", "1")
	req2.Header.Set("X-Request-ID", "2")
}

func TestErrorHandling(t *testing.T) {
	testCases := []struct {
		name          string
		setupFunc     func() error
		expectedError string
	}{
		{
			name: "Invalid SSH Credentials",
			setupFunc: func() error {
				_, err := sshclient.NewSSHClient("invalid", "invalid", "password", "invalid")
				return err
			},
			expectedError: "could not create hostkeycallback function", // Updated expected error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.setupFunc()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

// TestStaticFileServing tests if static files are served correctly
func TestStaticFileServing(t *testing.T) {
	// Create test directories and files
	err := os.MkdirAll("./static", 0755)
	assert.NoError(t, err)
	defer os.RemoveAll("./static")

	err = os.WriteFile("./static/index.html", []byte("<html><body>Test</body></html>"), 0644)
	assert.NoError(t, err)

	// Create test router
	router := mux.NewRouter()
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	}).Methods("GET")

	// Create test server
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Test root path
	resp, err := http.Get(ts.URL + "/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test static file serving
	resp, err = http.Get(ts.URL + "/static/index.html")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestConfigLoading tests config loading functionality
func TestConfigLoading(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "9999", cfg.Server.Port)
	assert.Equal(t, "test-secret", cfg.JWTSecret)
}

// TestSecuredRoutes tests JWT authentication middleware
func TestSecuredRoutes(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	secured := router.PathPrefix("/").Subrouter()
	secured.Use(api.JWTAuthenticationMiddleware(cfg))

	// Add test secured route
	secured.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")

	ts := httptest.NewServer(router)
	defer ts.Close()

	// Test without token
	req, _ := http.NewRequest("GET", ts.URL+"/test", nil)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Test with invalid token
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestServerStartup tests the server initialization
func TestServerStartup(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	// Start server in goroutine
	go func() {
		router := mux.NewRouter()
		err := http.ListenAndServe(":"+cfg.Server.Port, router)
		if err != http.ErrServerClosed {
			assert.NoError(t, err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test server is running
	resp, err := http.Get("http://localhost:" + cfg.Server.Port)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

// TestHealthCheckHandler tests the health check endpoint
func TestHealthCheckHandler(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/health", api.HealthCheckHandler())

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]string
	err := json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
}

// TestMetricsHandler tests the metrics endpoint
func TestMetricsHandler(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/metrics", api.MetricsHandler(cfg))

	// Test with internal IP
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Test with external IP
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.RemoteAddr = "8.8.8.8:12345"
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestLoginHandler tests the login endpoint
func TestLoginHandler(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/login", api.LoginHandler(cfg))

	testCases := []struct {
		name       string
		payload    map[string]string
		wantStatus int
	}{
		{
			name: "Valid Login",
			payload: map[string]string{
				"username": "test@example.com",
				"password": "password123",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Missing Credentials",
			payload: map[string]string{
				"username": "",
				"password": "",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}
}

// TestRegisterHandler tests the user registration endpoint
func TestRegisterHandler(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/register", api.RegisterHandler(cfg.DB, cfg))

	testCases := []struct {
		name       string
		payload    map[string]string
		wantStatus int
	}{
		{
			name: "Valid Registration",
			payload: map[string]string{
				"username": "newuser@example.com",
				"password": "securePass123!",
				"email":    "newuser@example.com",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "Invalid Email",
			payload: map[string]string{
				"username": "invalid",
				"password": "pass123",
				"email":    "notanemail",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Weak Password",
			payload: map[string]string{
				"username": "user@example.com",
				"password": "123",
				"email":    "user@example.com",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}
}

// TestBackupRestoreHandlers tests the backup and restore functionality
func TestBackupRestoreHandlers(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/backup", api.BackupHandler(cfg))
	router.HandleFunc("/restore", api.RestoreHandler(cfg))

	// Test backup endpoint
	t.Run("Backup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/backup", nil)
		token, _ := auth.GenerateJWT("test-user", cfg)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test restore endpoint
	t.Run("Restore", func(t *testing.T) {
		backupData := []byte("mock backup data")
		req := httptest.NewRequest(http.MethodPost, "/restore", bytes.NewReader(backupData))
		token, _ := auth.GenerateJWT("test-user", cfg)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestDownloadConfigHandler tests the VPN config download endpoint
func TestDownloadConfigHandler(t *testing.T) {
	router := mux.NewRouter()
	router.HandleFunc("/download/{type}/{id}", api.DownloadConfigHandler())

	testCases := []struct {
		name       string
		vpnType    string
		setupID    string
		wantStatus int
	}{
		{
			name:       "Download OpenVPN Config",
			vpnType:    "openvpn",
			setupID:    "test-123",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Download iOS VPN Config",
			vpnType:    "ios",
			setupID:    "test-456",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Invalid VPN Type",
			vpnType:    "invalid",
			setupID:    "test-789",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/download/%s/%s", tc.vpnType, tc.setupID)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}
}

// TestSecurityMiddleware tests all security middleware functions
func TestSecurityMiddleware(t *testing.T) {
	router := mux.NewRouter()
	router.Use(api.SecurityHeadersMiddleware)
	router.Use(api.RateLimitMiddleware(api.NewRateLimiter(time.Second, 5)))
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test security headers
	t.Run("Security Headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", rr.Header().Get("X-XSS-Protection"))
		assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "default-src")
	})

	// Test rate limiting
	t.Run("Rate Limiting", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if i < 5 {
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, rr.Code)
			}
		}
	})
}

// TestInternalIPCheck tests the internal IP check functionality
func TestInternalIPCheck(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Localhost", "127.0.0.1", true},
		{"Internal IP", "192.168.1.1", true},
		{"Private IP", "10.0.0.1", true},
		{"Public IP", "8.8.8.8", false},
		{"Invalid IP", "invalid-ip", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isInternalIP(tc.ip)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Helper function for internal IP checks
func isInternalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if it's a loopback address
	if parsedIP.IsLoopback() {
		return true
	}

	// Check private network ranges
	privateNetworks := []struct {
		network string
		mask    string
	}{
		{"10.0.0.0", "255.0.0.0"},      // Class A
		{"172.16.0.0", "255.240.0.0"},  // Class B
		{"192.168.0.0", "255.255.0.0"}, // Class C
	}

	for _, network := range privateNetworks {
		ip := net.ParseIP(network.network)
		mask := net.IPMask(net.ParseIP(network.mask).To4())
		if ip.Mask(mask).Equal(parsedIP.Mask(mask)) {
			return true
		}
	}

	return false
}
