// Package monitoring provides system metrics collection and monitoring.
//
// This package implements real-time monitoring of system metrics including
// CPU usage, memory usage, goroutine count, and request statistics.
// It supports both real-time monitoring and periodic metrics file writing.
package monitoring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// SystemMetrics holds various system performance metrics.
type SystemMetrics struct {
	// CPU usage percentage
	CPUUsage float64 `json:"cpu_usage"`

	// Memory usage in bytes
	MemoryUsage uint64 `json:"memory_usage"`

	// Number of active goroutines
	GoRoutines int `json:"goroutines"`

	// Server uptime in seconds
	Uptime float64 `json:"uptime_seconds"`

	// Disk usage in bytes
	DiskUsage uint64 `json:"disk_usage"`

	// Number of open file descriptors
	OpenFiles int `json:"open_files"`

	// Server start time
	StartTime time.Time `json:"start_time"`

	// From basic metrics
	ActiveConnections   int64   `json:"active_connections"`
	RequestCount        int64   `json:"request_count"`
	ErrorCount          int64   `json:"error_count"`
	AverageResponseTime float64 `json:"avg_response_time_ms"`

	// Additional info
	CollectedAt  string `json:"collected_at"`
	HostInfo     string `json:"host_info"`
	NumGoroutine int    `json:"num_goroutine"`
}

var (
	systemMetrics SystemMetrics
	metricsLock   sync.RWMutex
	startTime     = time.Now()
	metricsPath   string
)

// StartMetricsCollection begins periodic collection of system metrics.
// It runs as a goroutine and updates metrics every 30 seconds.
func StartMetricsCollection() {
	go collectMetrics()
}

func collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		updateSystemMetrics()
	}
}

func updateSystemMetrics() {
	metricsLock.Lock()
	defer metricsLock.Unlock()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	systemMetrics = SystemMetrics{
		GoRoutines:  runtime.NumGoroutine(),
		MemoryUsage: mem.Alloc,
		Uptime:      time.Since(startTime).Seconds(),
		StartTime:   startTime,
		DiskUsage:   0, // Platform-specific implementation removed
		OpenFiles:   0, // Platform-specific implementation removed
	}
}

// GetSystemMetrics returns the current system metrics.
// It provides a thread-safe way to access the latest metrics.
func GetSystemMetrics() SystemMetrics {
	metricsLock.RLock()
	defer metricsLock.RUnlock()
	return systemMetrics
}

// LogRequest records metrics about an HTTP request.
// It tracks request path, method, status, and duration.
func LogRequest(path, method string, status int, duration time.Duration) {
	logger.Log.Printf("Request tracked: %s %s %d %v", method, path, status, duration)
}

// LogError records error metrics and logs the error details.
func LogError(err error) {
	if err == nil {
		return
	}
	logger.Log.Printf("Error tracked: %v", err)
}

func WriteMetricsToFile() error {
	metrics := GetSystemMetrics()
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("metrics", 0755); err != nil {
		return err
	}

	if err := os.WriteFile("metrics/system_metrics.json", data, 0644); err != nil {
		return err
	}

	return nil
}

// InitMetrics initializes the metrics system with the given storage path
func InitMetrics(path string) {
	metricsPath = path

	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0755); err != nil {
		logger.Log.Printf("Error creating metrics directory: %v", err)
	}

	logger.Log.Printf("Metrics system initialized with path: %s", path)

	// Start a background routine to periodically collect and save metrics
	go periodicMetricsCollection()
}

// periodicMetricsCollection collects and saves metrics every minute
func periodicMetricsCollection() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		metrics := CollectSystemMetrics()
		if err := SaveMetrics(metrics); err != nil {
			logger.Log.Printf("Error saving periodic metrics: %v", err)
		}
	}
}

// CollectSystemMetrics gathers system metrics
func CollectSystemMetrics() *SystemMetrics {
	metrics := GetSystemMetrics()

	// Create system metrics object
	sysMetrics := &SystemMetrics{
		ActiveConnections:   metrics.ActiveConnections,
		RequestCount:        metrics.RequestCount,
		ErrorCount:          metrics.ErrorCount,
		AverageResponseTime: metrics.AverageResponseTime,
		GoRoutines:          runtime.NumGoroutine(),
		CollectedAt:         time.Now().Format(time.RFC3339),
		HostInfo:            runtime.GOOS + "/" + runtime.GOARCH,
		NumGoroutine:        runtime.NumGoroutine(),
	}

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	sysMetrics.MemoryUsage = memStats.Alloc

	// In a production system, we would add code here to measure actual CPU/Disk usage
	// This is simplified for this example
	sysMetrics.CPUUsage = 0.0 // Would need OS-specific code to get real CPU usage
	sysMetrics.DiskUsage = 0  // Would need OS-specific code to get disk usage

	return sysMetrics
}

// SaveMetrics saves the metrics to a JSON file
func SaveMetrics(metrics *SystemMetrics) error {
	if metricsPath == "" {
		metricsPath = "metrics" // Default path
	}

	// Ensure metrics directory exists
	if err := os.MkdirAll(metricsPath, 0755); err != nil {
		return err
	}

	// Create a timestamped filename
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := filepath.Join(metricsPath, "metrics-"+timestamp+".json")

	// Convert metrics to JSON
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}

	// Write metrics to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	// Also write the latest metrics to a fixed file
	latestFile := filepath.Join(metricsPath, "metrics-latest.json")
	if err := os.WriteFile(latestFile, data, 0644); err != nil {
		return err
	}

	logger.Log.Printf("Metrics saved to %s", filename)
	return nil
}
