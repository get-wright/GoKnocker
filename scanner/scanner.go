package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"GoKnocker/display"
	"GoKnocker/models"
	"GoKnocker/services"
	"GoKnocker/services/windows"
	"GoKnocker/stats"
)

type Scanner struct {
	host         string
	startPort    uint16
	endPort      uint16
	timeout      time.Duration
	rateLimit    time.Duration
	threads      int
	debug        bool
	maxRetries   int
	adjustRate   bool
	minRateLimit time.Duration
	maxRateLimit time.Duration
	retryDelay   time.Duration
	batchSize    int
	earlyTimeout time.Duration
	stats        *stats.ScanStats
	display      *display.ProgressDisplay
	detailed     bool
}

func NewScanner() *Scanner {
	return &Scanner{
		startPort:    1,
		endPort:      65535,
		timeout:      time.Second * 2,
		rateLimit:    time.Millisecond, // 1000 scans per second default
		threads:      500,
		maxRetries:   3,
		adjustRate:   true,
		minRateLimit: time.Millisecond,      // Max 1000 scans per second
		maxRateLimit: time.Millisecond * 10, // Min 100 scans per second
		retryDelay:   time.Millisecond * 100,
		batchSize:    1000,
		earlyTimeout: time.Millisecond * 500,
		detailed:     false,
	}
}

// Setter methods
func (s *Scanner) SetHost(host string)              { s.host = host }
func (s *Scanner) SetStartPort(port uint16)         { s.startPort = port }
func (s *Scanner) SetEndPort(port uint16)           { s.endPort = port }
func (s *Scanner) SetRateLimit(rate time.Duration)  { s.rateLimit = rate }
func (s *Scanner) SetTimeout(timeout time.Duration) { s.timeout = timeout }
func (s *Scanner) SetThreads(threads int)           { s.threads = threads }
func (s *Scanner) EnableDetailedStats(enabled bool) { s.detailed = enabled }

// Getter methods
func (s *Scanner) GetHost() string             { return s.host }
func (s *Scanner) GetStartPort() uint16        { return s.startPort }
func (s *Scanner) GetEndPort() uint16          { return s.endPort }
func (s *Scanner) GetRateLimit() time.Duration { return s.rateLimit }
func (s *Scanner) GetStats() *stats.ScanStats  { return s.stats }

// fastPortScan performs quick initial port scanning
func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- models.PortResult, wg *sync.WaitGroup) {
	defer wg.Done()

	dialer := &net.Dialer{
		Timeout:   s.earlyTimeout,
		KeepAlive: -1,
	}

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", s.host, port))

			if err == nil {
				conn.Close()
				results <- models.PortResult{
					IP:           net.ParseIP(s.host),
					Port:         port,
					State:        "open",
					ResponseTime: time.Since(start),
				}
			} else if strings.Contains(err.Error(), "refused") {
				s.stats.UpdatePortStatus("closed")
			} else {
				s.stats.UpdatePortStatus("filtered")
				s.stats.UpdateError()
			}

			s.stats.IncrementScanned()

			// Dynamic rate limiting
			if s.adjustRate {
				errorCount := s.stats.GetErrorCount()
				if errorCount > uint64(s.threads/2) {
					newRate := s.rateLimit * 2
					if newRate <= s.maxRateLimit {
						s.rateLimit = newRate
					}
				} else if errorCount == 0 && s.rateLimit > s.minRateLimit {
					newRate := s.rateLimit / 2
					if newRate >= s.minRateLimit {
						s.rateLimit = newRate
					}
				}
			}

			time.Sleep(s.rateLimit)
		}
	}
}

// validatePort performs thorough port validation and service detection
func (s *Scanner) validatePort(result *models.PortResult) {
	s.stats.SetPhase("Service Detection")

	for attempt := 0; attempt < s.maxRetries; attempt++ {
		address := fmt.Sprintf("%s:%d", s.host, result.Port)
		conn, err := net.DialTimeout("tcp", address, s.timeout)

		if err != nil {
			if strings.Contains(err.Error(), "refused") {
				result.State = "filtered"
			}
			s.stats.UpdateRetry()
			if attempt < s.maxRetries-1 {
				time.Sleep(s.retryDelay)
			}
			continue
		}

		defer conn.Close()
		banner := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		n, _ := conn.Read(banner)

		if n > 0 {
			result.Banner = banner[:n]
			if s.identifyService(result) {
				s.stats.UpdateServiceFound()
				return
			}
		}

		// Check Windows services
		if s.checkWindowsServices(result) {
			s.stats.UpdateServiceFound()
			return
		}

		// Check common ports
		if s.checkCommonPorts(result) {
			s.stats.UpdateServiceFound()
			return
		}
	}
}

func (s *Scanner) identifyService(result *models.PortResult) bool {
	fingerprint := services.NewFingerprint(result.Banner)
	if protocol := fingerprint.IdentifyProtocol(); protocol != "" {
		switch protocol {
		case "HTTP":
			if info := services.ProbeHTTP(s.host, result.Port, s.timeout, false); info != nil {
				result.Service = "HTTP"
				result.HttpInfo = info
				if info.Server != "" {
					result.Version = info.Server
				}
				return true
			}
		case "SSH":
			if service, version := services.TrySSH(fmt.Sprintf("%s:%d", s.host, result.Port), s.timeout); service != "" {
				result.Service = service
				result.Version = version
				return true
			}
		}
		result.Service = protocol
		result.Version = fingerprint.ExtractVersion()
		return true
	}
	return false
}

func (s *Scanner) checkWindowsServices(result *models.PortResult) bool {
	if service, version := windows.ProbeService(s.host, result.Port, s.timeout); service != "" {
		result.Service = service
		result.Version = version
		return true
	}
	return false
}

func (s *Scanner) checkCommonPorts(result *models.PortResult) bool {
	switch result.Port {
	case 80, 8080, 8000, 5000:
		if info := services.ProbeHTTP(s.host, result.Port, s.timeout, false); info != nil {
			result.Service = "HTTP"
			result.HttpInfo = info
			if info.Server != "" {
				result.Version = info.Server
			}
			return true
		}
	case 443, 8443:
		if info, enhanced := services.ProbeHTTPS(s.host, result.Port, s.timeout); info != nil {
			result.Service = "HTTPS"
			result.HttpInfo = info
			result.EnhancedInfo = enhanced
			if info.Server != "" {
				result.Version = info.Server
			}
			return true
		}
	}
	return false
}

func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	totalPorts := uint64(s.endPort - s.startPort + 1)
	s.stats = stats.NewScanStats(totalPorts, s.detailed)
	s.display = display.NewProgressDisplay(s.stats)

	// Start progress display
	go s.display.Start()
	defer s.display.Stop()

	resultsChan := make(chan models.PortResult, s.threads)
	ports := make(chan uint16, s.threads*2)

	// Start worker pool for fast scanning
	var wg sync.WaitGroup
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go s.fastPortScan(ctx, ports, resultsChan, &wg)
	}

	// Feed ports in batches
	go func() {
		for port := s.startPort; port <= s.endPort; port++ {
			select {
			case ports <- port:
			case <-ctx.Done():
				return
			}
		}
		close(ports)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results and perform service detection
	var openPorts []models.PortResult
	for result := range resultsChan {
		if result.State == "open" {
			s.validatePort(&result)
			openPorts = append(openPorts, result)
		}
	}

	// Sort results by port number
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts
}
