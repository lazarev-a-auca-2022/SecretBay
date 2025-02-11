package logger

import (
	"log"
	"os"
)

var Log *log.Logger

func init() {
	// Log to STDOUT with standard flags (date, time, etc.)
	Log = log.New(os.Stdout, "", log.LstdFlags)
}
