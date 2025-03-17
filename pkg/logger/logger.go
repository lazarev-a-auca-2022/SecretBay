// Package logger provides secure logging functionality with sensitive data redaction.
//
// This package implements logging with automatic redaction of sensitive information
// like passwords, tokens, and keys. It supports log rotation and multi-destination
// logging (file and stdout).
package logger

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Constants for log buffer
const (
	// maxLogSize defines the maximum size of a log file before rotation (10MB)
	maxLogSize = 10 * 1024 * 1024

	// maxLogFiles defines how many rotated log files to keep
	maxLogFiles = 5

	// logDirectory is the directory where log files are stored
	logDirectory = "logs"

	// logFile is the name of the main log file
	logFile = "vpn-server.log"

	// Maximum number of log entries to keep in memory
	MaxLogEntries = 1000
)

var (
	// Log is the global logger instance
	Log *log.Logger
	mu  sync.Mutex

	// Store the writers for flushing
	logWriters []io.Writer

	// Store buffered writers that need flushing
	bufferedWriters []flushableWriter

	// Debug flag to control verbose logging
	debugEnabled bool

	// Output writer
	logOutput io.Writer

	// In-memory buffer of recent logs for API access
	logBuffer     []string
	logBufferLock sync.RWMutex
)

// flushableWriter is an interface for writers that can be flushed
type flushableWriter interface {
	io.Writer
	Flush() error
}

// bufferedWriterImpl implements the flushableWriter interface
type bufferedWriterImpl struct {
	writer *bufio.Writer
}

func (bw *bufferedWriterImpl) Write(p []byte) (n int, err error) {
	return bw.writer.Write(p)
}

func (bw *bufferedWriterImpl) Flush() error {
	return bw.writer.Flush()
}

// sensitivePatterns defines regex patterns for data that should be redacted
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`password[:=].*`),
	regexp.MustCompile(`token[:=].*`),
	regexp.MustCompile(`secret[:=].*`),
	regexp.MustCompile(`key[:=].*`),
	regexp.MustCompile(`auth_credential[:=].*`),
}

// Regular expressions for sensitive data redaction
var (
	passwordRegex = regexp.MustCompile(`(?i)(password|passwd|pass|pwd)[:=]\s*['"]?([^'")\s]+)`)
	keyRegex      = regexp.MustCompile(`(?i)(api_?key|secret|token)[:=]\s*['"]?([^'")\s]+)`)
	jwtRegex      = regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,})`)
)

func init() {
	// Create a buffered writer for stdout to prevent blocking
	stdoutWriter := NewBufferedWriter(os.Stdout)
	logWriters = []io.Writer{stdoutWriter}
	bufferedWriters = append(bufferedWriters, stdoutWriter)

	// Only write to file if not in Docker
	if os.Getenv("DOCKER_CONTAINER") != "true" {
		if err := os.MkdirAll(logDirectory, 0755); err != nil {
			log.Printf("Failed to create log directory: %v", err)
		} else {
			logPath := filepath.Join(logDirectory, logFile)
			file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
			if err != nil {
				log.Printf("Failed to open log file: %v", err)
			} else {
				fileWriter := NewBufferedWriter(file)
				logWriters = append(logWriters, fileWriter)
				bufferedWriters = append(bufferedWriters, fileWriter)
				go rotateLogFiles()
			}
		}
	}

	// Create multi-writer
	multiWriter := io.MultiWriter(logWriters...)
	Log = log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lshortfile)

	// Initialize log buffer
	logBuffer = make([]string, 0, MaxLogEntries)
}

// NewBufferedWriter creates a buffered writer that can be flushed
func NewBufferedWriter(w io.Writer) flushableWriter {
	// Create a buffered writer with a generous buffer size for efficiency
	buffered := bufio.NewWriterSize(w, 4096)
	return &bufferedWriterImpl{writer: buffered}
}

// sanitizeMessage redacts sensitive information from log messages.
// It replaces matched patterns with <REDACTED>.
func sanitizeMessage(message string) string {
	for _, pattern := range sensitivePatterns {
		message = pattern.ReplaceAllString(message, "${1}=<REDACTED>")
	}
	return message
}

// Printf logs a formatted message after sanitizing sensitive information.
// It's a thread-safe wrapper around log.Printf with data redaction.
func Printf(format string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	message := fmt.Sprintf(format, v...)
	sanitized := sanitizeMessage(message)
	Log.Output(2, sanitized)

	// Add to buffer for API access
	addToBuffer(sanitized)

	// Flush all writers immediately
	FlushAll()
}

// Println logs a message after sanitizing sensitive information.
// It's a thread-safe wrapper around log.Println with data redaction.
func Println(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	message := fmt.Sprintln(v...)
	sanitized := sanitizeMessage(message)
	Log.Output(2, sanitized)

	// Add to buffer for API access
	addToBuffer(sanitized)

	// Flush all writers immediately
	FlushAll()
}

// FlushAll forces a flush on all writers that support it
func FlushAll() {
	for _, writer := range bufferedWriters {
		_ = writer.Flush()
	}
}

// SetOutput sets the output destination for the logger
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	logOutput = w
	Log.SetOutput(w)
}

// SetDebug enables or disables debug logging
func SetDebug(enabled bool) {
	debugEnabled = enabled
}

// Debug logs a debug message if debug mode is enabled
func Debug(format string, v ...interface{}) {
	if debugEnabled {
		message := fmt.Sprintf(format, v...)
		message = redactSensitiveData(message)
		Log.Printf("[DEBUG] %s", message)
		addToBuffer(fmt.Sprintf("[DEBUG] %s", message))
	}
}

// Info logs an informational message
func Info(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	message = redactSensitiveData(message)
	Log.Printf("[INFO] %s", message)
	addToBuffer(fmt.Sprintf("[INFO] %s", message))
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	message = redactSensitiveData(message)
	Log.Printf("[WARN] %s", message)
	addToBuffer(fmt.Sprintf("[WARN] %s", message))
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	message = redactSensitiveData(message)
	Log.Printf("[ERROR] %s", message)
	addToBuffer(fmt.Sprintf("[ERROR] %s", message))
}

// Fatal logs a fatal error message and exits
func Fatal(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	message = redactSensitiveData(message)
	Log.Fatalf("[FATAL] %s", message)
	// No need to add to buffer as the program will exit
}

// redactSensitiveData removes sensitive data from log messages
func redactSensitiveData(message string) string {
	// Replace passwords
	message = passwordRegex.ReplaceAllString(message, "$1: [REDACTED]")

	// Replace API keys and secrets
	message = keyRegex.ReplaceAllString(message, "$1: [REDACTED]")

	// Replace JWTs (keep first 10 chars)
	message = jwtRegex.ReplaceAllStringFunc(message, func(token string) string {
		if len(token) > 10 {
			return token[:10] + "..."
		}
		return token
	})

	return message
}

// addToBuffer adds a log message to the in-memory buffer
func addToBuffer(message string) {
	// Add timestamp if not already present
	if len(message) < 20 || message[0] != '[' {
		message = fmt.Sprintf("[%s] %s", time.Now().Format("2006/01/02 15:04:05"), message)
	}

	logBufferLock.Lock()
	defer logBufferLock.Unlock()

	// Add to buffer with circular behavior
	if len(logBuffer) >= MaxLogEntries {
		// Shift all elements left, discarding oldest
		logBuffer = append(logBuffer[1:], message)
	} else {
		logBuffer = append(logBuffer, message)
	}
}

// GetRecentLogs returns the most recent logs from the buffer
func GetRecentLogs(count int) ([]string, error) {
	logBufferLock.RLock()
	defer logBufferLock.RUnlock()

	if count <= 0 || count > MaxLogEntries {
		count = MaxLogEntries
	}

	if len(logBuffer) == 0 {
		return []string{"No logs available"}, nil
	}

	// Return the most recent 'count' logs or all if there are fewer
	start := len(logBuffer) - count
	if start < 0 {
		start = 0
	}

	result := make([]string, len(logBuffer)-start)
	copy(result, logBuffer[start:])

	return result, nil
}

func rotateLogFiles() {
	for {
		time.Sleep(1 * time.Hour)

		mu.Lock()
		logPath := filepath.Join(logDirectory, logFile)
		info, err := os.Stat(logPath)
		if err != nil {
			mu.Unlock()
			continue
		}

		if info.Size() < maxLogSize {
			mu.Unlock()
			continue
		}

		// Rotate files
		for i := maxLogFiles - 1; i >= 0; i-- {
			oldPath := fmt.Sprintf("%s.%d", logPath, i)
			newPath := fmt.Sprintf("%s.%d", logPath, i+1)

			if i == 0 {
				oldPath = logPath
			}

			if _, err := os.Stat(oldPath); err == nil {
				if i == maxLogFiles-1 {
					os.Remove(oldPath)
				} else {
					os.Rename(oldPath, newPath)
				}
			}
		}

		// Create new log file
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
		if err == nil {
			// Update the writer
			fileWriter := NewBufferedWriter(file)

			// Replace file writer in our slices
			for i, w := range logWriters {
				if _, ok := w.(flushableWriter); ok {
					logWriters[i] = fileWriter
					break
				}
			}

			for i, w := range bufferedWriters {
				if _, ok := w.(flushableWriter); ok {
					bufferedWriters[i] = fileWriter
					break
				}
			}

			// Recreate the multi-writer
			multiWriter := io.MultiWriter(logWriters...)
			Log.SetOutput(multiWriter)
		}

		mu.Unlock()
	}
}
