package scanner

import (
	"log"
	"os"
	"sync"
	"time"
)

type DebugLogger struct {
	enabled bool
	logger  *log.Logger
	mu      sync.Mutex
}

func NewDebugLogger(enabled bool) *DebugLogger {
	logger := &DebugLogger{
		enabled: enabled,
		logger:  log.New(os.Stdout, "[DEBUG] ", log.Ldate|log.Ltime|log.Lmicroseconds),
	}
	return logger
}

func (d *DebugLogger) Log(format string, v ...interface{}) {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logger.Printf(format, v...)
}

func (d *DebugLogger) LogPortScan(port uint16, state string, duration time.Duration) {
	d.Log("Port %d scan completed: %s (%v)", port, state, duration)
}

func (d *DebugLogger) LogServiceProbe(port uint16, service string, success bool) {
	d.Log("Port %d service probe [%s]: %v", port, service, success)
}

func (d *DebugLogger) LogBanner(port uint16, banner []byte) {
	if len(banner) > 0 {
		d.Log("Port %d banner: %q", port, banner)
	}
}

func (d *DebugLogger) LogError(port uint16, err error) {
	d.Log("Port %d error: %v", port, err)
}
