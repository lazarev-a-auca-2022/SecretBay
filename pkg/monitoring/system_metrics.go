// Package monitoring provides system metrics collection and monitoring.
//
// This package implements real-time monitoring of system metrics including
// CPU usage, memory usage, goroutine count, and request statistics.
// It supports both real-time monitoring and periodic metrics file writing.
package monitoring

import (
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// SystemMetrics holds various system performance metrics.
type SystemMetrics struct {
	// CPU usage percentage
	CPU float64 `json:"cpu_usage"`

	// Memory usage percentage
	Memory float64 `json:"memory_usage"`

	// Number of active goroutines
	Goroutines int `json:"goroutines"`

	// Server uptime duration string
	Uptime string `json:"uptime"`

	// Disk usage percentage
	DiskUsage float64 `json:"disk_usage"`

	// Number of open file descriptors
	OpenFiles int `json:"open_files"`

	// Server start time
	StartTime time.Time `json:"start_time"`
}

var (
	systemMetrics SystemMetrics
	metricsLock   sync.RWMutex
	startTime     = time.Now()
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
		Goroutines: runtime.NumGoroutine(),
		Memory:     float64(mem.Alloc) / float64(mem.Sys) * 100,
		Uptime:     time.Since(startTime).String(),
		StartTime:  startTime,
		DiskUsage:  0, // Platform-specific implementation removed
		OpenFiles:  0, // Platform-specific implementation removed
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
