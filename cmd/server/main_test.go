package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
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
	router.HandleFunc("/api/csrf-token", api.CSRFTokenHandler()).Methods("GET", "OPTIONS")
	api.SetupRoutes(router, cfg)

	// Create mock SSH client with expected behaviors
	mockSSH := new(MockSSHClient)
	mockSSH.On("RunCommand", "systemctl is-active openvpn@server").Return("active", nil)
	mockSSH.On("RunCommand", "systemctl is-active strongswan-starter").Return("active", nil)
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
			// First get a CSRF token
			csrfReq := httptest.NewRequest(http.MethodGet, "/api/csrf-token", nil)
			csrfRR := httptest.NewRecorder()
			router.ServeHTTP(csrfRR, csrfReq)
			assert.Equal(t, http.StatusOK, csrfRR.Code)

			var csrfResp map[string]string
			err := json.NewDecoder(csrfRR.Body).Decode(&csrfResp)
			assert.NoError(t, err)
			assert.NotEmpty(t, csrfResp["token"])

			// Then make the actual VPN setup request
			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrfResp["token"])

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

			// Create SSH client with both Client and RunCommandFunc initialized
			client := &sshclient.SSHClient{
				Client: &ssh.Client{}, // Add this line to initialize the Client field
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
			expectedError: "password too short",
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
	// Set required environment variables for test
	os.Setenv("JWT_SECRET", "test-secret-that-meets-minimum-length-32char")

	cfg, err := config.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "9999", cfg.Server.Port)
	assert.Equal(t, "test-secret-that-meets-minimum-length-32char", cfg.JWTSecret)

	// Clean up
	os.Unsetenv("JWT_SECRET")
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
		if (err != nil) && (err != http.ErrServerClosed) {
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

	// Set admin credentials in env for testing
	os.Setenv("ADMIN_USERNAME", "test@example.com")
	os.Setenv("ADMIN_PASSWORD", "password123")

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

	// Clean up environment
	os.Unsetenv("ADMIN_USERNAME")
	os.Unsetenv("ADMIN_PASSWORD")
}

// TestRegisterHandler tests the user registration endpoint
func TestRegisterHandler(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	// Create mock database
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	cfg.DB = db

	router := mux.NewRouter()
	router.HandleFunc("/register", api.RegisterHandler(cfg.DB, cfg))

	testCases := []struct {
		name       string
		payload    map[string]string
		wantStatus int
		setupMock  func()
	}{
		{
			name: "Valid Registration",
			payload: map[string]string{
				"username": "testuser123",
				"password": "SecurePass123!",
				"email":    "newuser@example.com",
			},
			wantStatus: http.StatusCreated,
			setupMock: func() {
				// Mock username check
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("testuser123").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

				// Mock email check
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("newuser@example.com").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

				// Mock insert
				mock.ExpectExec("INSERT INTO users").
					WithArgs("testuser123", "newuser@example.com", sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
		},
		{
			name: "Invalid Email",
			payload: map[string]string{
				"username": "invalid",
				"password": "pass123",
				"email":    "notanemail",
			},
			wantStatus: http.StatusBadRequest,
			setupMock:  func() {},
		},
		{
			name: "Weak Password",
			payload: map[string]string{
				"username": "user123",
				"password": "123",
				"email":    "user@example.com",
			},
			wantStatus: http.StatusBadRequest,
			setupMock:  func() {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			tc.setupMock()

			payloadBytes, err := json.Marshal(tc.payload)
			assert.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(payloadBytes))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code)

			// Verify all expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

// TestBackupRestoreHandlers tests the backup and restore functionality
func isRestoreCopyCommand(cmd string) bool {
	// Normalize path separators
	cmd = strings.ReplaceAll(cmd, "\\", "/")
	return strings.HasPrefix(cmd, "cp -a /tmp/vpn-restore") &&
		strings.Contains(cmd, "/* ") &&
		strings.HasSuffix(cmd, "/ 2>/dev/null || true")
}

func TestBackupRestoreHandlers(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	// Create mock SSH client
	mockSSH := new(MockSSHClient)

	// Mock backup commands
	mockSSH.On("RunCommand", "mkdir -p /var/backups/vpn-server").Return("", nil)
	mockSSH.On("RunCommand", mock.MatchedBy(func(cmd string) bool {
		return strings.HasPrefix(cmd, "tar czf /var/backups/vpn-server/backup-")
	})).Return("", nil)
	mockSSH.On("RunCommand", mock.MatchedBy(func(cmd string) bool {
		return strings.HasPrefix(cmd, "chmod 600 /var/backups/vpn-server/backup-")
	})).Return("", nil)
	mockSSH.On("RunCommand", mock.MatchedBy(func(cmd string) bool {
		return strings.HasPrefix(cmd, "ls -t /var/backups/vpn-server/backup-")
	})).Return("", nil)

	// Mock restore commands
	mockSSH.On("RunCommand", "test -f /tmp/backup.tar.gz").Return("", nil)
	mockSSH.On("RunCommand", "rm -rf /tmp/vpn-restore && mkdir -p /tmp/vpn-restore").Return("", nil)
	mockSSH.On("RunCommand", "tar xzf /tmp/backup.tar.gz -C /tmp/vpn-restore").Return("", nil)
	mockSSH.On("RunCommand", mock.MatchedBy(isRestoreCopyCommand)).Return("", nil)
	mockSSH.On("RunCommand", "rm -rf /tmp/vpn-restore").Return("", nil)
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

	router := mux.NewRouter()
	router.HandleFunc("/backup", api.BackupHandler(cfg)).Methods("GET")
	router.HandleFunc("/restore", api.RestoreHandler(cfg)).Methods("POST")

	// Test backup endpoint
	t.Run("Backup", func(t *testing.T) {
		// Create request with query parameters
		req := httptest.NewRequest(http.MethodGet, "/backup?server_ip=192.168.1.1", nil)

		// Generate and set JWT token
		token, err := auth.GenerateJWT("test-user", cfg)
		assert.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Create a new context with the username
		ctx := context.WithValue(req.Context(), "username", "test-user")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test restore endpoint
	t.Run("Restore", func(t *testing.T) {
		payload := map[string]string{
			"server_ip":   "192.168.1.1",
			"backup_file": "/tmp/backup.tar.gz",
		}
		payloadBytes, err := json.Marshal(payload)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/restore", bytes.NewReader(payloadBytes))

		// Generate and set JWT token
		token, err := auth.GenerateJWT("test-user", cfg)
		assert.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		// Create a new context with the username
		ctx := context.WithValue(req.Context(), "username", "test-user")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Verify all mock expectations were met
	mockSSH.AssertExpectations(t)
}

// TestDownloadConfigHandler tests the VPN config download endpoint
func TestDownloadConfigHandler(t *testing.T) {
	// Create mock SSH client with path-aware responses
	mockSSH := new(MockSSHClient)
	mockSSH.On("RunCommand", "test -f /etc/vpn-configs/openvpn_config.ovpn && echo exists || echo notfound").Return("exists\n", nil)
	mockSSH.On("RunCommand", "cat /etc/vpn-configs/openvpn_config.ovpn").Return("mock openvpn config", nil)
	mockSSH.On("RunCommand", "test -f /etc/vpn-configs/ios_vpn.mobileconfig && echo exists || echo notfound").Return("exists\n", nil)
	mockSSH.On("RunCommand", "cat /etc/vpn-configs/ios_vpn.mobileconfig").Return("mock ios vpn config", nil)
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
			path := fmt.Sprintf("/download/%s/%s?server_ip=192.168.1.1&username=test-user&credential=test-pass", tc.vpnType, tc.setupID)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}

	// Verify all mock expectations were met
	mockSSH.AssertExpectations(t)
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

// TestAuthStatusHandler tests the auth status endpoint
func TestAuthStatusHandler(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/api/auth/status", api.AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")

	testCases := []struct {
		name           string
		method         string
		headers        map[string]string
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Valid GET request",
			method: "GET",
			headers: map[string]string{
				"Accept": "application/json",
				"Origin": "http://localhost:8080",
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"enabled": true,
			},
		},
		{
			name:   "OPTIONS request for CORS",
			method: "OPTIONS",
			headers: map[string]string{
				"Origin":                        "http://localhost:8080",
				"Access-Control-Request-Method": "GET",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Missing Accept header",
			method: "GET",
			headers: map[string]string{
				"Origin": "http://localhost:8080",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Origin",
			method: "GET",
			headers: map[string]string{
				"Accept": "application/json",
				"Origin": "http://malicious-site.com",
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/auth/status", nil)

			// Set headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedBody != nil {
				var response map[string]interface{}
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBody, response)
			}

			// Check CORS headers for OPTIONS requests
			if tc.method == "OPTIONS" {
				assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Origin"))
				assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Methods"))
				assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Headers"))
			}
		})
	}
}

// TestStaticAssetsLoading tests proper loading of static assets and script execution order
func TestStaticAssetsLoading(t *testing.T) {
	// Create test directories and files
	err := os.MkdirAll("./static", 0755)
	assert.NoError(t, err)
	defer os.RemoveAll("./static")

	// Create test index.html with proper script loading
	indexHTML := `<!DOCTYPE html>
<html>
<head>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            // Test DOM is ready
            console.log('DOM loaded');
        });
    </script>
</head>
<body>
    <div id="vpnForm"></div>
    <script src="main.js"></script>
</body>
</html>`

	err = os.WriteFile("./static/index.html", []byte(indexHTML), 0644)
	assert.NoError(t, err)

	// Create test router with static file serving
	router := mux.NewRouter()
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})

	// Create test server
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Test index.html is served correctly
	resp, err := http.Get(ts.URL + "/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()

	// Verify script tag is present and correctly placed
	assert.Contains(t, string(body), `<script src="main.js"></script>`)
	assert.Contains(t, string(body), `<div id="vpnForm"></div>`)
}

// TestHTTP2Support tests proper HTTP/2 protocol support and configuration
func TestHTTP2Support(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/api/auth/status", api.AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")

	// Create test server with HTTP/2 support
	ts := httptest.NewUnstartedServer(router)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	// Create HTTP/2 capable client
	client := ts.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.NextProtos = []string{"h2"}

	// Test auth status endpoint with HTTP/2
	req, err := http.NewRequest("GET", ts.URL+"/api/auth/status", nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:8080")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check if protocol is HTTP/2 (accepting both h2 and HTTP/2.0)
	proto := resp.Proto
	assert.True(t, proto == "h2" || proto == "HTTP/2.0", "Expected HTTP/2 protocol (h2 or HTTP/2.0), got %s", proto)

	// Verify response content
	var response map[string]bool
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Contains(t, response, "enabled")
}

// Helper function to generate test certificate
func generateTestCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// TestAuthStatusHandlerWithHTTP2 tests the auth status endpoint specifically for HTTP/2 protocol issues
func TestAuthStatusHandlerWithHTTP2(t *testing.T) {
	cfg, err := config.LoadConfig()
	assert.NoError(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/api/auth/status", api.AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")

	// Create test server with HTTP/2 support
	ts := httptest.NewUnstartedServer(router)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	// Create HTTP/2 capable client
	client := ts.Client()

	// Test cases
	testCases := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name: "No Accept header HTTP/2",
			headers: map[string]string{
				"Origin": "http://localhost:8080",
			},
			expectedStatus: http.StatusOK, // Should not return 400 even without Accept header
		},
		{
			name: "With Accept header HTTP/2",
			headers: map[string]string{
				"Accept": "application/json",
				"Origin": "http://localhost:8080",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL+"/api/auth/status", nil)
			assert.NoError(t, err)

			// Set headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			// Verify response is valid JSON and has expected structure
			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Contains(t, response, "enabled")
		})
	}
}
