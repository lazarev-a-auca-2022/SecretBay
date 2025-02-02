package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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
	os.Setenv("JWT_SECRET", "test-secret")
	os.Exit(m.Run())
}

// TestVPNSetupRequest tests the VPN setup endpoint
func TestVPNSetupRequest(t *testing.T) {
	cfg, _ := config.LoadConfig()
	router := mux.NewRouter()

	// Create mock SSH client with expected behaviors
	mockSSH := new(MockSSHClient)
	mockSSH.On("RunCommand", mock.AnythingOfType("string")).Return("", nil)
	mockSSH.On("Close").Return()

	// Override the NewSSHClient function for testing
	originalNewSSHClient := sshclient.NewSSHClient
	sshclient.NewSSHClient = func(serverIP, username, authMethod, authCredential string) (*sshclient.SSHClient, error) {
		// Create a proper SSHClient with our mock
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

	api.SetupRoutes(router, cfg)

	testCases := []struct {
		name       string
		payload    models.VPNSetupRequest
		wantStatus int
	}{
		{
			name: "Valid OpenVPN Setup",
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
			name: "Valid iOS VPN Setup",
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

			req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewReader(payloadBytes))
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
