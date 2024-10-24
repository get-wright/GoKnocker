package scanner

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"GoKnocker/models"
)

type ScanStatistics struct {
	mutex sync.RWMutex

	StartTime     time.Time
	PortsScanned  uint64
	TotalPorts    uint64
	OpenPorts     int
	Services      map[string]int
	ResponseTimes []time.Duration
	CurrentPort   uint16
	ErrorCount    uint64
	lastUpdate    time.Time
	lastPortCount uint64
	scanRate      float64
}

func NewScanStatistics(totalPorts uint64) *ScanStatistics {
	return &ScanStatistics{
		StartTime:     time.Now(),
		TotalPorts:    totalPorts,
		Services:      make(map[string]int),
		ResponseTimes: make([]time.Duration, 0),
		lastUpdate:    time.Now(),
	}
}

func (s *ScanStatistics) UpdateProgress(scannedPorts uint64, currentPort uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.PortsScanned = scannedPorts
	s.CurrentPort = currentPort

	// Update scan rate every second
	now := time.Now()
	if now.Sub(s.lastUpdate) >= time.Second {
		portDelta := s.PortsScanned - s.lastPortCount
		timeDelta := now.Sub(s.lastUpdate).Seconds()
		if timeDelta > 0 {
			s.scanRate = float64(portDelta) / timeDelta
		}
		s.lastUpdate = now
		s.lastPortCount = s.PortsScanned
	}
}

func (s *ScanStatistics) AddResult(result models.PortResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.OpenPorts++
	if result.Service != "" && result.Service != "unknown" {
		s.Services[result.Service]++
	}
	s.ResponseTimes = append(s.ResponseTimes, result.ResponseTime)

	// Track additional metrics
	if result.HttpInfo != nil {
		if result.HttpInfo.TLSVersion != "" {
			s.Services["TLS"]++
		}
		if result.HttpInfo.StatusCode >= 400 {
			s.Services["ErrorPages"]++
		}
	}
}

func (s *ScanStatistics) IncrementErrors() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.ErrorCount++
}

func (s *ScanStatistics) GetAverageResponseTime() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.ResponseTimes) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range s.ResponseTimes {
		total += t
	}
	return total / time.Duration(len(s.ResponseTimes))
}

func (s *ScanStatistics) GetScanRate() float64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.scanRate
}

func (s *ScanStatistics) String() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var b strings.Builder

	// Calculate progress bar with bounds checking
	progress := s.GetProgress()
	width := 40
	// Ensure progress is between 0 and 100
	progress = math.Max(0, math.Min(100, progress))
	complete := int(progress * float64(width) / 100)
	// Ensure complete is between 0 and width
	complete = int(math.Max(0, math.Min(float64(width), float64(complete))))
	remaining := width - complete

	// Progress bar with validated values
	b.WriteString(fmt.Sprintf("\033[2K\rProgress: [%s%s] %.1f%%\n",
		strings.Repeat("=", complete),
		strings.Repeat(" ", remaining),
		progress))

	// Scan time and current status
	elapsed := time.Since(s.StartTime).Round(time.Second)
	b.WriteString(fmt.Sprintf("Scan Time: %v\n", elapsed))
	b.WriteString(fmt.Sprintf("Current Port: %d\n", s.CurrentPort))

	// Ports scanned with rate
	b.WriteString(fmt.Sprintf("Ports Scanned: %d/%d (%.0f ports/sec)\n",
		s.PortsScanned, s.TotalPorts, s.scanRate))

	// Open ports count
	b.WriteString(fmt.Sprintf("Open Ports Found: %d\n", s.OpenPorts))

	// Service distribution
	if len(s.Services) > 0 {
		b.WriteString("\nServices Found:\n")
		services := make([]struct {
			name  string
			count int
		}, 0, len(s.Services))

		for name, count := range s.Services {
			services = append(services, struct {
				name  string
				count int
			}{name, count})
		}

		sort.Slice(services, func(i, j int) bool {
			return services[i].count > services[j].count
		})

		for _, svc := range services {
			b.WriteString(fmt.Sprintf("  %-10s: %d\n", svc.name, svc.count))
		}
	}

	// Average response time
	if len(s.ResponseTimes) > 0 {
		b.WriteString(fmt.Sprintf("\nAverage Response Time: %v\n", s.GetAverageResponseTime()))
	}

	// Error count if any
	if s.ErrorCount > 0 {
		b.WriteString(fmt.Sprintf("Errors Encountered: %d\n", s.ErrorCount))
	}

	return b.String()
}

// Improve progress calculation
func (s *ScanStatistics) GetProgress() float64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.TotalPorts == 0 {
		return 0
	}

	progress := float64(s.PortsScanned) / float64(s.TotalPorts) * 100
	// Ensure progress is between 0 and 100
	return math.Max(0, math.Min(100, progress))
}
