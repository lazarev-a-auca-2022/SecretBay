// Package logger provides secure logging functionality with sensitive data redaction.
//
// This package implements logging with automatic redaction of sensitive information
// like passwords, tokens, and keys. It supports log rotation and multi-destination
// logging (file and stdout).
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var (
	// Log is the global logger instance
	Log *log.Logger
	mu  sync.Mutex
)

const (
	// maxLogSize defines the maximum size of a log file before rotation (10MB)
	maxLogSize = 10 * 1024 * 1024

	// maxLogFiles defines how many rotated log files to keep
	maxLogFiles = 5

	// logDirectory is the directory where log files are stored
	logDirectory = "logs"

	// logFile is the name of the main log file
	logFile = "vpn-server.log"
)

// sensitivePatterns defines regex patterns for data that should be redacted
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`password[:=].*`),
	regexp.MustCompile(`token[:=].*`),
	regexp.MustCompile(`secret[:=].*`),
	regexp.MustCompile(`key[:=].*`),
	regexp.MustCompile(`auth_credential[:=].*`),
}

func init() {
	// Create multi-writer to write to both file and stdout
	writers := []io.Writer{os.Stdout}

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
				writers = append(writers, file)
				go rotateLogFiles()
			}
		}
	}

	// Create multi-writer
	multiWriter := io.MultiWriter(writers...)
	Log = log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lshortfile)
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
}

// Println logs a message after sanitizing sensitive information.
// It's a thread-safe wrapper around log.Println with data redaction.
func Println(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	message := fmt.Sprintln(v...)
	sanitized := sanitizeMessage(message)
	Log.Output(2, sanitized)
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
			Log.SetOutput(file)
		}

		mu.Unlock()
	}
}
