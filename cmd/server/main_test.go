package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/stretchr/testify/assert"
)

// TestMain runs before all tests to setup test environment
func TestMain(m *testing.M) {
	// Setup test environment
	os.Setenv("SERVER_PORT", "9999")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Exit(m.Run())
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
