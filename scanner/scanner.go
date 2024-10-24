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
	results      chan models.PortResult
	progress     chan float64
	maxRetries   int
	adjustRate   bool
	minRateLimit time.Duration
	maxRateLimit time.Duration
	retryDelay   time.Duration
	batchSize    int
	earlyTimeout time.Duration
	stats        *ScanStatistics
	statInterval time.Duration
}

type portScanResult struct {
	port       uint16
	isOpen     bool
	response   time.Duration
	errorCount int
	scanErrors []error
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
		results:      make(chan models.PortResult),
		progress:     make(chan float64, 100),
		statInterval: time.Second * 2, // Update stats every 2 seconds
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

func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
	s.earlyTimeout = timeout / 4
}

func (s *Scanner) SetThreads(threads int) {
	s.threads = threads
}

func (s *Scanner) SetRateLimit(rate time.Duration) {
	s.rateLimit = rate
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

func (s *Scanner) GetTimeout() time.Duration {
	return s.timeout
}

func (s *Scanner) GetThreads() int {
	return s.threads
}

func (s *Scanner) GetRateLimit() time.Duration {
	return s.rateLimit
}

func (s *Scanner) GetProgressChan() chan float64 {
	return s.progress
}

func (s *Scanner) printStatistics(ctx context.Context) {
	ticker := time.NewTicker(s.statInterval)
	defer ticker.Stop()

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h") // Show cursor on exit

	// Clear screen once at the start
	fmt.Print("\033[2J\033[H")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Print statistics
			fmt.Print(s.stats.String())

			// Move cursor back to top
			fmt.Print("\033[H")
		}
	}
}

// Improve rate limiting in fastPortScan
func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- portScanResult, errorRate *uint64) {
	dialer := &net.Dialer{
		Timeout:   s.earlyTimeout,
		KeepAlive: -1,
	}

	rateLimiter := time.NewTicker(s.rateLimit)
	defer rateLimiter.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case port, ok := <-ports:
			if !ok {
				return
			}

			<-rateLimiter.C

			result := portScanResult{
				port:       port,
				scanErrors: make([]error, 0),
			}

			// Quick check with context timeout
			dialCtx, cancel := context.WithTimeout(ctx, s.earlyTimeout)
			conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", s.host, port))
			cancel()

			if err == nil {
				conn.Close()
				result.isOpen = true
				result.response = s.earlyTimeout
			} else if !strings.Contains(err.Error(), "refused") {
				atomic.AddUint64(errorRate, 1)
				result.errorCount++
				result.scanErrors = append(result.scanErrors, err)
				s.stats.IncrementErrors()
			}

			// Update statistics
			atomic.AddUint64(&s.stats.PortsScanned, 1)
			s.stats.UpdateProgress(atomic.LoadUint64(&s.stats.PortsScanned), port)

			// Send result if port is open
			if result.isOpen {
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// scanner/scanner.go

func (s *Scanner) validatePort(port uint16, initialResponse time.Duration) models.PortResult {
	result := models.PortResult{
		IP:           net.ParseIP(s.host),
		Port:         port,
		State:        "open",
		ResponseTime: initialResponse,
	}

	address := fmt.Sprintf("%s:%d", s.host, port)

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			result.State = "filtered"
		}
		return result
	}
	defer conn.Close()

	// Set read deadline and increase buffer size for better banner capture
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	banner := make([]byte, 4096) // Increased from 1024
	n, _ := conn.Read(banner)

	if n > 0 {
		result.Banner = bytes.TrimSpace(banner[:n])
		fingerprint := services.NewFingerprint(banner[:n])

		// Check for SSL/TLS on all ports, not just standard ones
		if info, enhanced := services.ProbeHTTPS(s.host, port, s.timeout); info != nil {
			result.Service = "https"
			result.HttpInfo = info
			result.EnhancedInfo = enhanced
			if info.Server != "" {
				result.Version = info.Server
			}
			s.stats.AddResult(result)
			return result
		}

		// Use fingerprint.go's enhanced protocol detection
		if protocol := fingerprint.IdentifyProtocol(); protocol != "" {
			// ... (rest of the switch case remains the same)
		}

		// Improve common ports detection with Windows services
		if result.Service == "" {
			if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
				result.Service = service
				result.Version = version
			}
		}
	}

	if result.State == "open" {
		s.stats.AddResult(result)
	}
	return result
}

// scanner/scanner.go

func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	totalPorts := uint64(s.endPort - s.startPort + 1)
	s.stats = NewScanStatistics(totalPorts)

	var errorRate uint64

	// Start statistics printer
	statsDone := make(chan struct{})
	go func() {
		s.printStatistics(ctx)
		close(statsDone)
	}()

	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	// Increase buffer sizes to prevent blocking
	ports := make(chan uint16, s.threads*4)
	fastScanResults := make(chan portScanResult, s.threads*4)

	// Start port scanners with proper error handling
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Recovered from scanner panic: %v\n", r)
				}
			}()
			s.fastPortScan(ctx, ports, fastScanResults, &errorRate)
		}()
	}

	// Feed ports with non-blocking send
	portFeederDone := make(chan struct{})
	go func() {
		defer close(portFeederDone)
		currentPort := s.startPort
		for currentPort <= s.endPort {
			select {
			case <-ctx.Done():
				return
			default:
				select {
				case ports <- currentPort:
					currentPort++
				case <-ctx.Done():
					return
				}
			}
		}
		close(ports)
	}()

	// Process results with timeout
	resultsDone := make(chan struct{})
	go func() {
		defer close(resultsDone)
		for {
			select {
			case result, ok := <-fastScanResults:
				if !ok {
					return
				}
				if result.isOpen {
					fullResult := s.validatePort(result.port, result.response)
					if fullResult.State == "open" {
						resultsMutex.Lock()
						results = append(results, fullResult)
						resultsMutex.Unlock()
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for port feeding to complete
	<-portFeederDone

	// Wait for all scanners with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Normal completion
	case <-time.After(time.Second * 30):
		// Timeout - cancel context and clean up
		cancel()
	}

	// Clean up
	close(fastScanResults)

	// Wait for result processing to complete
	<-resultsDone

	// Cancel statistics and wait for completion
	cancel()
	<-statsDone

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Final progress update
	s.stats.UpdateProgress(totalPorts, s.endPort)

	return results
}
