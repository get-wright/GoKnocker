package stats

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type ScanStats struct {
	startTime     time.Time
	portsScanned  uint64
	totalPorts    uint64
	openPorts     uint64
	filteredPorts uint64
	closedPorts   uint64
	currentRate   uint64
	//avgResponseMs  uint64
	retryCount     uint64
	errorCount     uint64
	servicesFound  uint64
	currentPhase   string
	enableDetails  bool
	lastUpdateTime time.Time
	rateHistory    []uint64
}

// NewScanStats creates a new statistics tracker
func NewScanStats(totalPorts uint64, enableDetails bool) *ScanStats {
	return &ScanStats{
		startTime:      time.Now(),
		lastUpdateTime: time.Now(),
		totalPorts:     totalPorts,
		enableDetails:  enableDetails,
		currentPhase:   "Fast Scan",
		rateHistory:    make([]uint64, 0, 10),
	}
}

// IncrementScanned atomically increments the scanned ports counter
func (s *ScanStats) IncrementScanned() {
	atomic.AddUint64(&s.portsScanned, 1)
	s.updateRate()
}

func (s *ScanStats) UpdatePortStatus(status string) {
	switch status {
	case "open":
		atomic.AddUint64(&s.openPorts, 1)
	case "filtered":
		atomic.AddUint64(&s.filteredPorts, 1)
	case "closed":
		atomic.AddUint64(&s.closedPorts, 1)
	}
}

// UpdateServiceFound increments the services found counter
func (s *ScanStats) UpdateServiceFound() {
	atomic.AddUint64(&s.servicesFound, 1)
}

// UpdateError increments the error counter
func (s *ScanStats) UpdateError() {
	atomic.AddUint64(&s.errorCount, 1)
}

// UpdateRetry increments the retry counter
func (s *ScanStats) UpdateRetry() {
	atomic.AddUint64(&s.retryCount, 1)
}

// SetPhase updates the current scanning phase
func (s *ScanStats) SetPhase(phase string) {
	s.currentPhase = phase
}

// Getter methods
func (s *ScanStats) GetErrorCount() uint64 {
	return atomic.LoadUint64(&s.errorCount)
}

func (s *ScanStats) GetRetryCount() uint64 {
	return atomic.LoadUint64(&s.retryCount)
}

func (s *ScanStats) GetOpenPorts() uint64 {
	return atomic.LoadUint64(&s.openPorts)
}

func (s *ScanStats) GetFilteredPorts() uint64 {
	return atomic.LoadUint64(&s.filteredPorts)
}

func (s *ScanStats) GetClosedPorts() uint64 {
	return atomic.LoadUint64(&s.closedPorts)
}

func (s *ScanStats) GetServicesFound() uint64 {
	return atomic.LoadUint64(&s.servicesFound)
}

func (s *ScanStats) GetCurrentPhase() string {
	return s.currentPhase
}

func (s *ScanStats) IsDetailedEnabled() bool {
	return s.enableDetails
}

func (s *ScanStats) GetProgress() float64 {
	scanned := atomic.LoadUint64(&s.portsScanned)
	return float64(scanned) / float64(s.totalPorts) * 100
}

func (s *ScanStats) IsComplete() bool {
	return atomic.LoadUint64(&s.portsScanned) >= s.totalPorts
}

func (s *ScanStats) updateRate() {
	now := time.Now()
	elapsed := now.Sub(s.lastUpdateTime).Seconds()
	if elapsed >= 1.0 {
		scanned := atomic.LoadUint64(&s.portsScanned)
		rate := uint64(float64(scanned) / elapsed)
		s.rateHistory = append(s.rateHistory, rate)
		if len(s.rateHistory) > 10 {
			s.rateHistory = s.rateHistory[1:]
		}
		atomic.StoreUint64(&s.currentRate, rate)
		s.lastUpdateTime = now
	}
}

func (s *ScanStats) getAverageRate() uint64 {
	if len(s.rateHistory) == 0 {
		return 0
	}
	var sum uint64
	for _, rate := range s.rateHistory {
		sum += rate
	}
	return sum / uint64(len(s.rateHistory))
}

func (s *ScanStats) FormatProgressBar(width int) string {
	progress := s.GetProgress()
	rate := s.getAverageRate()

	// Calculate remaining time
	scanned := atomic.LoadUint64(&s.portsScanned)
	remaining := s.totalPorts - scanned
	var eta string
	if rate > 0 {
		etaSeconds := float64(remaining) / float64(rate)
		eta = formatDuration(time.Duration(etaSeconds) * time.Second)
	} else {
		eta = "calculating..."
	}

	// Calculate bar width (subtract space needed for percentage and brackets)
	barWidth := width - 20 // Account for percentage and ETA
	completed := int(float64(barWidth) * progress / 100)

	bar := fmt.Sprintf("[%s%s] %.1f%% ETA: %s",
		strings.Repeat("=", completed),
		strings.Repeat(" ", barWidth-completed),
		progress,
		eta)

	if !s.enableDetails {
		return bar
	}

	// Add detailed statistics below the progress bar
	stats := fmt.Sprintf("\n\rScan Statistics:"+
		"\n\r• Phase: %s"+
		"\n\r• Ports/sec: %d (avg: %d)"+
		"\n\r• Open: %d, Filtered: %d, Closed: %d"+
		"\n\r• Services identified: %d"+
		"\n\r• Retries: %d, Errors: %d"+
		"\n\r• Elapsed: %v",
		s.GetCurrentPhase(),
		atomic.LoadUint64(&s.currentRate),
		s.getAverageRate(),
		s.GetOpenPorts(),
		s.GetFilteredPorts(),
		s.GetClosedPorts(),
		s.GetServicesFound(),
		s.GetRetryCount(),
		s.GetErrorCount(),
		formatDuration(time.Since(s.startTime)))

	return bar + stats
}

// formatDuration formats a duration in a human-readable format
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
