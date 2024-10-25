package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"GoKnocker/models"
	"GoKnocker/services"
	"GoKnocker/services/fingerprint"
	"GoKnocker/services/windows"
)

type Scanner struct {
	host              string
	startPort         uint16
	endPort           uint16
	timeout           time.Duration
	rateLimit         time.Duration
	threads           int
	debug             bool
	results           chan models.PortResult
	progress          chan float64
	maxRetries        int
	adjustRate        bool
	minRateLimit      time.Duration
	maxRateLimit      time.Duration
	serviceIdentifier *fingerprint.ServiceIdentifier
	customPorts       map[uint16]string
	debugLogger       *DebugLogger
}

func NewScanner() *Scanner {
	s := &Scanner{
		startPort:    1,
		endPort:      65535,
		timeout:      time.Second * 2,        // Reduced default timeout
		rateLimit:    time.Millisecond,       // 1000 scans per second default
		threads:      500,                    // Increased default threads
		maxRetries:   2,                      // Number of retries for validation
		adjustRate:   true,                   // Enable dynamic rate adjustment
		minRateLimit: time.Microsecond * 500, // Max 2000 scans per second
		maxRateLimit: time.Millisecond * 5,   // Min 200 scans per second
		results:      make(chan models.PortResult),
		progress:     make(chan float64),
		customPorts:  make(map[uint16]string),
		debugLogger:  NewDebugLogger(false),
	}
	s.serviceIdentifier = fingerprint.NewServiceIdentifier(s.timeout)
	return s
}

// Setter methods
func (s *Scanner) SetHost(host string) {
	s.host = host
}

func (s *Scanner) SetStartPort(port uint16) {
	s.startPort = port
}

func (s *Scanner) SetEndPort(port uint16) {
	s.endPort = port
}

func (s *Scanner) SetRateLimit(rate time.Duration) {
	s.rateLimit = rate
}

func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Scanner) SetThreads(threads int) {
	s.threads = threads
}

// Getter methods
func (s *Scanner) GetHost() string {
	return s.host
}

func (s *Scanner) GetStartPort() uint16 {
	return s.startPort
}

func (s *Scanner) GetEndPort() uint16 {
	return s.endPort
}

func (s *Scanner) GetRateLimit() time.Duration {
	return s.rateLimit
}

func (s *Scanner) GetProgressChan() chan float64 {
	return s.progress
}

func (s *Scanner) AddCustomPort(port uint16, serviceName string) {
	s.customPorts[port] = serviceName
}

func (s *Scanner) SetDebug(enabled bool) {
	s.debugLogger = NewDebugLogger(enabled)
}

type portScanResult struct {
	port     uint16
	isOpen   bool
	response time.Duration
}

// fastPortScan performs quick initial port scanning
func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- portScanResult, errorRate *uint64) {
	dialer := &net.Dialer{
		Timeout: s.timeout / 2,
	}

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
			start := time.Now()
			address := fmt.Sprintf("%s:%d", s.host, port)
			s.debugLogger.Log("Attempting connection to %s", address)

			conn, err := dialer.DialContext(ctx, "tcp", address)
			duration := time.Since(start)

			if err == nil {
				conn.Close()
				s.debugLogger.Log("Port %d is open (took %v)", port, duration)
				results <- portScanResult{
					port:     port,
					isOpen:   true,
					response: duration,
				}
			} else {
				s.debugLogger.Log("Port %d is closed/filtered: %v", port, err)
				if !strings.Contains(err.Error(), "refused") {
					atomic.AddUint64(errorRate, 1)
				}
			}

			// Rate limiting debug
			if s.adjustRate {
				errorRateValue := atomic.LoadUint64(errorRate)
				s.debugLogger.Log("Current error rate: %d, rate limit: %v", errorRateValue, s.rateLimit)
			}

			select {
			case <-time.After(s.rateLimit):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scanner) validatePort(port uint16, initialResponse time.Duration) models.PortResult {
	s.debugLogger.Log("Validating port %d (initial response: %v)", port, initialResponse)

	result := models.PortResult{
		IP:           net.ParseIP(s.host),
		Port:         port,
		State:        "closed",
		ResponseTime: initialResponse,
	}

	// First check well-known ports and their specific handlers
	switch port {
	case 80, 8080, 8000, 5000, 3000:
		s.debugLogger.Log("Attempting HTTP probe on port %d", port)
		if info := services.ProbeHTTP(s.host, port, s.timeout, false); info != nil {
			result.Service = "HTTP"
			result.HttpInfo = info
			result.State = "open"
			if info.Server != "" {
				result.Version = info.Server
			}
			return result
		}

	case 443, 8443:
		s.debugLogger.Log("Attempting HTTPS probe on port %d", port)
		if info, enhanced := services.ProbeHTTPS(s.host, port, s.timeout); info != nil {
			result.Service = "HTTPS"
			result.HttpInfo = info
			result.EnhancedInfo = enhanced
			result.State = "open"
			if info.Server != "" {
				result.Version = info.Server
			}
			return result
		}

	case 22:
		s.debugLogger.Log("Attempting SSH probe on port %d", port)
		if service, version := services.TrySSH(fmt.Sprintf("%s:%d", s.host, port), s.timeout); service != "" {
			result.Service = service
			result.Version = version
			result.State = "open"
			return result
		}
	}

	// Check custom port mappings
	if expectedService, ok := s.customPorts[port]; ok {
		s.debugLogger.Log("Port %d has custom mapping to service: %s", port, expectedService)
		if service, version := s.serviceIdentifier.IdentifyService(s.host, port); service != "" {
			s.debugLogger.Log("Service detected on port %d: %s (version: %s)", port, service, version)
			if strings.EqualFold(service, expectedService) {
				result.Service = service
				result.Version = version
				result.State = "open"
				return result
			}
			result.Service = service
			result.Version = fmt.Sprintf("%s (Expected: %s)", version, expectedService)
			result.State = "open"
			return result
		}
	}

	// Try Windows service detection
	if _, ok := windows.ServicePorts[port]; ok {
		s.debugLogger.Log("Attempting Windows service detection on port %d", port)
		if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
			s.debugLogger.Log("Windows service detected on port %d: %s (version: %s)", port, service, version)
			result.Service = service
			result.Version = version
			result.State = "open"
			return result
		}
	}

	// If port is open but no specific service detected, try general service fingerprinting
	if service, version := s.serviceIdentifier.IdentifyService(s.host, port); service != "" {
		s.debugLogger.Log("Fingerprint detected on port %d: %s (version: %s)", port, service, version)
		result.Service = service
		result.Version = version
		result.State = "open"
		return result
	}

	// Finally, fall back to banner grab
	address := fmt.Sprintf("%s:%d", s.host, port)
	s.debugLogger.Log("Attempting banner grab on port %d", port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		s.debugLogger.LogError(port, err)
		if strings.Contains(err.Error(), "refused") {
			result.State = "filtered"
		}
		return result
	}
	defer conn.Close()

	result.State = "open"
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		s.debugLogger.LogError(port, err)
	}
	if n > 0 {
		result.Banner = bytes.TrimSpace(banner[:n])
		s.debugLogger.LogBanner(port, result.Banner)
	}

	return result
}

// scanner/scanner.go

func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	// Channels for the scan pipeline
	ports := make(chan uint16, s.threads*2)
	fastScanResults := make(chan portScanResult, s.threads*2)

	// Error rate tracking
	var errorRate uint64

	// Progress tracking with smaller buffer
	totalPorts := int64(s.endPort - s.startPort + 1)
	scanned := int64(0)

	// Make progress channel buffered
	s.progress = make(chan float64, totalPorts)

	// More frequent progress updates
	progressTicker := time.NewTicker(50 * time.Millisecond)
	defer progressTicker.Stop()

	// Start fast port scanners
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.fastPortScan(ctx, ports, fastScanResults, &errorRate)
		}()
	}

	// Feed ports to scan with progress tracking
	go func() {
		defer close(ports)
		for port := s.startPort; port <= s.endPort; port++ {
			select {
			case ports <- port:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Process results with progress updates
	go func() {
		for result := range fastScanResults {
			newCount := atomic.AddInt64(&scanned, 1)
			progress := float64(newCount) / float64(totalPorts) * 100

			// Try to send progress update
			select {
			case s.progress <- progress:
			default:
				// Skip if channel is full
			}

			if result.isOpen {
				fullResult := s.validatePort(result.port, result.response)
				if fullResult.State == "open" {
					resultsMutex.Lock()
					results = append(results, fullResult)
					resultsMutex.Unlock()
				}
			}
		}
	}()

	// Additional progress monitoring goroutine
	go func() {
		lastProgress := float64(0)
		for {
			select {
			case <-progressTicker.C:
				currentCount := atomic.LoadInt64(&scanned)
				progress := float64(currentCount) / float64(totalPorts) * 100

				// Only send if progress has changed
				if progress > lastProgress {
					select {
					case s.progress <- progress:
						lastProgress = progress
					default:
						// Skip if channel is full
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for completion
	wg.Wait()
	close(fastScanResults)

	// Ensure 100% progress is sent
	s.progress <- 100.0
	close(s.progress)

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
