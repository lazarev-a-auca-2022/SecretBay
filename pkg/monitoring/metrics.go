package monitoring

import (
	"sync"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type Metrics struct {
	ActiveConnections   int64
	RequestCount        int64
	ErrorCount          int64
	AverageResponseTime float64
	LastError           string
	LastErrorTime       time.Time
	mu                  sync.RWMutex
}

var defaultMetrics = &Metrics{}

func GetMetrics() *Metrics {
	defaultMetrics.mu.RLock()
	defer defaultMetrics.mu.RUnlock()

	// Return a copy to prevent external modification
	return &Metrics{
		ActiveConnections:   defaultMetrics.ActiveConnections,
		RequestCount:        defaultMetrics.RequestCount,
		ErrorCount:          defaultMetrics.ErrorCount,
		AverageResponseTime: defaultMetrics.AverageResponseTime,
		LastError:           defaultMetrics.LastError,
		LastErrorTime:       defaultMetrics.LastErrorTime,
	}
}

func IncrementConnections() {
	defaultMetrics.mu.Lock()
	defaultMetrics.ActiveConnections++
	defaultMetrics.mu.Unlock()
}

func DecrementConnections() {
	defaultMetrics.mu.Lock()
	if defaultMetrics.ActiveConnections > 0 {
		defaultMetrics.ActiveConnections--
	}
	defaultMetrics.mu.Unlock()
}

func TrackRequest(duration time.Duration) {
	defaultMetrics.mu.Lock()
	defaultMetrics.RequestCount++
	// Update moving average
	defaultMetrics.AverageResponseTime = (defaultMetrics.AverageResponseTime*float64(defaultMetrics.RequestCount-1) + float64(duration.Milliseconds())) / float64(defaultMetrics.RequestCount)
	defaultMetrics.mu.Unlock()
}

func TrackError(err error) {
	if err == nil {
		return
	}

	defaultMetrics.mu.Lock()
	defaultMetrics.ErrorCount++
	defaultMetrics.LastError = err.Error()
	defaultMetrics.LastErrorTime = time.Now()
	defaultMetrics.mu.Unlock()

	// Log the error
	logger.Log.Printf("Error tracked: %v", err)
}
