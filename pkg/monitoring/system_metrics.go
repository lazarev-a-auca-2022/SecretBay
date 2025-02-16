package monitoring

import (
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type SystemMetrics struct {
	CPU        float64   `json:"cpu_usage"`
	Memory     float64   `json:"memory_usage"`
	Goroutines int       `json:"goroutines"`
	Uptime     string    `json:"uptime"`
	DiskUsage  float64   `json:"disk_usage"`
	OpenFiles  int       `json:"open_files"`
	StartTime  time.Time `json:"start_time"`
}

var (
	systemMetrics SystemMetrics
	metricsLock   sync.RWMutex
	startTime     = time.Now()
)

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

func GetSystemMetrics() SystemMetrics {
	metricsLock.RLock()
	defer metricsLock.RUnlock()
	return systemMetrics
}

// LogRequest logs request metrics
func LogRequest(path, method string, status int, duration time.Duration) {
	logger.Log.Printf("Request tracked: %s %s %d %v", method, path, status, duration)
}

// LogError logs error metrics
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
