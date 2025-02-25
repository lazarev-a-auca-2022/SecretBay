package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidatePath checks if a path is safe and within allowed directories
func ValidatePath(path string, allowedDirs []string) error {
	// Clean the path to handle ., .., and multiple slashes
	cleanPath := filepath.Clean(path)

	// Check if path tries to escape using ../
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		return fmt.Errorf("path traversal attempted")
	}

	// Verify path is within allowed directories
	allowed := false
	for _, dir := range allowedDirs {
		cleanDir := filepath.Clean(dir)
		if strings.HasPrefix(cleanPath, cleanDir) {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("path is not within allowed directories")
	}

	return nil
}

// SafeJoin safely joins path elements
func SafeJoin(basePath string, elem ...string) (string, error) {
	// Clean the base path
	basePath = filepath.Clean(basePath)

	// Join all elements
	fullPath := filepath.Join(append([]string{basePath}, elem...)...)

	// Verify the result is still under base path
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(basePath)) {
		return "", fmt.Errorf("path escapes base directory")
	}

	return fullPath, nil
}
