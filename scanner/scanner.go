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
	attempts   int
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

	// Save cursor position and hide it
	fmt.Print("\033[s\033[?25l")
	defer fmt.Print("\033[u\033[?25h") // Restore cursor position and show it

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Move cursor up by the number of lines in the stats
			fmt.Print("\033[2K") // Clear line
			stats := s.stats.String()
			numLines := strings.Count(stats, "\n") + 1
			if numLines > 0 {
				fmt.Printf("\033[%dA", numLines) // Move cursor up
			}
			fmt.Print(stats)
		}
	}
}

func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- portScanResult, errorRate *uint64) {
	dialer := &net.Dialer{
		Timeout:   s.earlyTimeout,
		KeepAlive: -1,
	}

	rateLimiter := time.NewTicker(s.rateLimit)
	defer rateLimiter.Stop()

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		case <-rateLimiter.C:
			result := portScanResult{
				port:       port,
				scanErrors: make([]error, 0),
			}

			// Multiple quick checks for consistency with better error tracking
			for i := 0; i < 2; i++ {
				result.attempts++
				start := time.Now()

				// Add context timeout
				dialCtx, cancel := context.WithTimeout(ctx, s.earlyTimeout)
				conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", s.host, port))
				cancel()

				if err == nil {
					conn.Close()
					result.isOpen = true
					response := time.Since(start)
					if result.response == 0 || response < result.response {
						result.response = response
					}
					break
				} else {
					if !strings.Contains(err.Error(), "refused") {
						atomic.AddUint64(errorRate, 1)
						result.errorCount++
						result.scanErrors = append(result.scanErrors, err)
						s.stats.IncrementErrors()
					}
					if strings.Contains(err.Error(), "refused") {
						break
					}
				}

				if i < 1 && !result.isOpen {
					time.Sleep(s.retryDelay / 2)
				}
			}

			// Update scan statistics
			atomic.AddUint64(&s.stats.PortsScanned, 1)
			s.stats.UpdateProgress(atomic.LoadUint64(&s.stats.PortsScanned), port)

			if result.isOpen {
				results <- result
			}

			// Dynamic rate limiting with smoother adjustments
			if s.adjustRate {
				errorRateValue := atomic.LoadUint64(errorRate)
				if errorRateValue > uint64(s.threads/4) { // More sensitive threshold
					atomic.StoreUint64(errorRate, 0)
					newRate := s.rateLimit + (s.rateLimit / 4) // Smaller increments
					if newRate <= s.maxRateLimit {
						s.rateLimit = newRate
						rateLimiter.Reset(s.rateLimit)
					}
				} else if errorRateValue == 0 && s.rateLimit > s.minRateLimit {
					newRate := s.rateLimit - (s.rateLimit / 4) // Smaller decrements
					if newRate >= s.minRateLimit {
						s.rateLimit = newRate
						rateLimiter.Reset(s.rateLimit)
					}
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

func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	totalPorts := uint64(s.endPort - s.startPort + 1)
	s.stats = NewScanStatistics(totalPorts)

	// Start statistics printer
	go s.printStatistics(ctx)

	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	ports := make(chan uint16, s.threads*2)
	fastScanResults := make(chan portScanResult, s.threads*2)

	var errorRate uint64

	// Start port scanners
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.fastPortScan(ctx, ports, fastScanResults, &errorRate)
		}()
	}

	// Feed ports in batches
	go func() {
		currentPort := s.startPort
		for currentPort <= s.endPort {
			batchEnd := currentPort + uint16(s.batchSize)
			if batchEnd > s.endPort {
				batchEnd = s.endPort
			}

			for port := currentPort; port <= batchEnd; port++ {
				select {
				case ports <- port:
				case <-ctx.Done():
					return
				}
			}

			time.Sleep(s.retryDelay)
			currentPort = batchEnd + 1
		}
		close(ports)
	}()

	// Process results
	go func() {
		for result := range fastScanResults {
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

	wg.Wait()
	close(fastScanResults)

	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Ensure final progress update
	s.stats.UpdateProgress(totalPorts, s.endPort)
	close(s.progress)

	return results
}
