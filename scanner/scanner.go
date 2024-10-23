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
	"GoKnocker/services/windows"
)

type Scanner struct {
	host         string
	startPort    uint16
	endPort      uint16
	timeout      time.Duration
	rateLimit    time.Duration
	threads      int
	debug        bool
	results      chan models.PortResult
	progress     chan float64
	maxRetries   int
	adjustRate   bool
	minRateLimit time.Duration
	maxRateLimit time.Duration
}

func NewScanner() *Scanner {
	return &Scanner{
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
	}
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

type portScanResult struct {
	port     uint16
	isOpen   bool
	response time.Duration
}

// fastPortScan performs quick initial port scanning
func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- portScanResult, errorRate *uint64) {
	dialer := &net.Dialer{
		Timeout: s.timeout / 2, // Shorter timeout for initial scan
	}

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
			start := time.Now()
			address := fmt.Sprintf("%s:%d", s.host, port)
			conn, err := dialer.DialContext(ctx, "tcp", address)

			if err == nil {
				conn.Close()
				results <- portScanResult{
					port:     port,
					isOpen:   true,
					response: time.Since(start),
				}
			} else if !strings.Contains(err.Error(), "refused") {
				atomic.AddUint64(errorRate, 1)
			}

			// Dynamic rate limiting based on error rate
			if s.adjustRate {
				errorRateValue := atomic.LoadUint64(errorRate)
				if errorRateValue > 10 && s.rateLimit < s.maxRateLimit {
					s.rateLimit += time.Microsecond * 100
				} else if errorRateValue < 5 && s.rateLimit > s.minRateLimit {
					s.rateLimit -= time.Microsecond * 50
				}
			}

			select {
			case <-time.After(s.rateLimit):
			case <-ctx.Done():
				return
			}
		}
	}
}

// validatePort performs thorough port and service detection
func (s *Scanner) validatePort(port uint16, initialResponse time.Duration) models.PortResult {
	result := models.PortResult{
		IP:           net.ParseIP(s.host),
		Port:         port,
		State:        "closed",
		ResponseTime: initialResponse,
	}

	var successfulProbe bool

	// Multiple validation attempts
	for attempt := 0; attempt < s.maxRetries && !successfulProbe; attempt++ {
		address := fmt.Sprintf("%s:%d", s.host, port)
		conn, err := net.DialTimeout("tcp", address, s.timeout)
		if err != nil {
			if strings.Contains(err.Error(), "refused") {
				result.State = "filtered"
			}
			continue
		}

		result.State = "open"
		defer conn.Close()
		successfulProbe = true

		// Check Windows services first
		if _, ok := windows.ServicePorts[port]; ok {
			if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
				result.Service = service
				result.Version = version
				return result
			}
		}

		// Check other common services
		switch port {
		case 22:
			if service, version := services.TrySSH(address, s.timeout); service != "" {
				result.Service = service
				result.Version = version
				return result
			}

		case 80, 8080, 8000, 5000:
			if info := services.ProbeHTTP(s.host, port, s.timeout, false); info != nil {
				result.Service = "HTTP"
				result.HttpInfo = info
				if info.Server != "" {
					result.Version = info.Server
				}
				return result
			}

		case 443, 8443:
			if info, enhanced := services.ProbeHTTPS(s.host, port, s.timeout); info != nil {
				result.Service = "HTTPS"
				result.HttpInfo = info
				result.EnhancedInfo = enhanced
				if info.Server != "" {
					result.Version = info.Server
				}
				return result
			}
		}

		// Try banner grab for unknown services
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		banner := make([]byte, 1024)
		n, _ := conn.Read(banner)
		if n > 0 {
			result.Banner = bytes.TrimSpace(banner[:n])
			// Try to identify service from banner
			if service, version := identifyServiceFromBanner(result.Banner); service != "" {
				result.Service = service
				result.Version = version
			}
		}
	}

	return result
}

// identifyServiceFromBanner attempts to identify service based on banner
func identifyServiceFromBanner(banner []byte) (string, string) {
	bannerStr := string(banner)

	// Common banner patterns
	if strings.Contains(bannerStr, "SSH-") {
		parts := strings.SplitN(bannerStr, " ", 2)
		version := ""
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}
		return "SSH", version
	}

	if strings.Contains(bannerStr, "HTTP") {
		return "HTTP", ""
	}

	if strings.Contains(bannerStr, "FTP") {
		return "FTP", ""
	}

	if strings.Contains(bannerStr, "SMTP") {
		return "SMTP", ""
	}

	if strings.Contains(bannerStr, "POP3") {
		return "POP3", ""
	}

	if strings.Contains(bannerStr, "IMAP") {
		return "IMAP", ""
	}

	return "", ""
}

// Scan performs the complete port scanning process
func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	// Channels for the scan pipeline
	ports := make(chan uint16, s.threads*2)
	fastScanResults := make(chan portScanResult, s.threads*2)

	// Error rate tracking for dynamic rate adjustment
	var errorRate uint64

	// Progress tracking
	totalPorts := uint64(s.endPort - s.startPort + 1)
	scanned := uint64(0)

	// Start fast port scanners
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.fastPortScan(ctx, ports, fastScanResults, &errorRate)
		}()
	}

	// Feed ports to scan
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

	// Process results
	go func() {
		for result := range fastScanResults {
			atomic.AddUint64(&scanned, 1)
			progress := float64(atomic.LoadUint64(&scanned)) / float64(totalPorts) * 100
			select {
			case s.progress <- progress:
			default:
			}

			if result.isOpen {
				// Validate and get service info
				fullResult := s.validatePort(result.port, result.response)
				if fullResult.State == "open" {
					resultsMutex.Lock()
					results = append(results, fullResult)
					resultsMutex.Unlock()
				}
			}
		}
	}()

	// Wait for scan completion
	wg.Wait()
	close(fastScanResults)
	close(s.progress)

	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
