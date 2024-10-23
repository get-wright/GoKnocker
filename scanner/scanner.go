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
	host          string
	startPort     uint16
	endPort       uint16
	timeout       time.Duration
	rateLimit     time.Duration
	threads       int
	debug         bool
	results       chan models.PortResult
	progress      chan float64
	maxRetries    int
	adjustRate    bool
	minRateLimit  time.Duration
	maxRateLimit  time.Duration
	retryDelay    time.Duration
	batchSize     int
	earlyTimeout  time.Duration
	progressMutex sync.Mutex
	lastProgress  float64
}

type portScanResult struct {
	port     uint16
	isOpen   bool
	response time.Duration
	attempts int
}

func NewScanner() *Scanner {
	return &Scanner{
		startPort:    1,
		endPort:      65535,
		timeout:      time.Second * 2,
		rateLimit:    time.Millisecond, // 1000 scans per second default
		threads:      500,
		maxRetries:   3, // Multiple validation attempts
		adjustRate:   true,
		minRateLimit: time.Millisecond,       // Max 1000 scans per second
		maxRateLimit: time.Millisecond * 10,  // Min 100 scans per second
		retryDelay:   time.Millisecond * 100, // Delay between retries
		batchSize:    1000,                   // Process ports in batches
		earlyTimeout: time.Millisecond * 500, // Quick initial check timeout
		results:      make(chan models.PortResult),
		progress:     make(chan float64, 100), // Buffered progress channel
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
	s.earlyTimeout = timeout / 4
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

// updateProgress ensures monotonic progress updates
func (s *Scanner) updateProgress(progress float64) {
	s.progressMutex.Lock()
	defer s.progressMutex.Unlock()

	if progress > s.lastProgress {
		s.lastProgress = progress
		select {
		case s.progress <- progress:
		default:
		}
	}
}

// fastPortScan performs quick initial port scanning
func (s *Scanner) fastPortScan(ctx context.Context, ports chan uint16, results chan<- portScanResult, errorRate *uint64) {
	dialer := &net.Dialer{
		Timeout:   s.earlyTimeout,
		KeepAlive: -1, // Disable keep-alive
	}

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
			var isOpen bool
			var bestResponse time.Duration
			attempts := 0

			// Multiple quick checks for consistency
			for i := 0; i < 2; i++ {
				attempts++
				start := time.Now()
				conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", s.host, port))

				if err == nil {
					conn.Close()
					isOpen = true
					response := time.Since(start)
					if bestResponse == 0 || response < bestResponse {
						bestResponse = response
					}
					break // Success, no need for more attempts
				} else {
					if !strings.Contains(err.Error(), "refused") {
						atomic.AddUint64(errorRate, 1)
					}
					// If connection was refused, it's definitely closed
					if strings.Contains(err.Error(), "refused") {
						break
					}
				}

				if i < 1 { // Don't sleep after last attempt
					time.Sleep(s.retryDelay / 2)
				}
			}

			if isOpen {
				results <- portScanResult{
					port:     port,
					isOpen:   true,
					response: bestResponse,
					attempts: attempts,
				}
			}

			// Dynamic rate limiting with error rate consideration
			if s.adjustRate {
				errorRateValue := atomic.LoadUint64(errorRate)
				if errorRateValue > uint64(s.threads/2) {
					atomic.StoreUint64(errorRate, 0)
					newRate := s.rateLimit * 2
					if newRate <= s.maxRateLimit {
						s.rateLimit = newRate
					}
				} else if errorRateValue == 0 && s.rateLimit > s.minRateLimit {
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
			if attempt < s.maxRetries-1 {
				time.Sleep(s.retryDelay)
			}
			continue
		}

		result.State = "open"
		defer conn.Close()
		successfulProbe = true

		// Get initial banner for protocol detection
		banner := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		n, _ := conn.Read(banner)

		if n > 0 {
			result.Banner = bytes.TrimSpace(banner[:n])

			// Try to identify service based on protocol fingerprint
			fingerprint := services.NewFingerprint(banner[:n])
			if protocol := fingerprint.IdentifyProtocol(); protocol != "" {
				switch protocol {
				case "HTTP":
					if info := services.ProbeHTTP(s.host, port, s.timeout, false); info != nil {
						result.Service = "HTTP"
						result.HttpInfo = info
						if info.Server != "" {
							result.Version = info.Server
						}
						return result
					}

				case "SSH":
					if service, version := services.TrySSH(address, s.timeout); service != "" {
						result.Service = service
						result.Version = version
						return result
					}

				case "SMB", "LDAP", "DNS", "RPC":
					if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
						result.Service = service
						result.Version = version
						return result
					}

				default:
					// For other identified protocols, at least set the service name
					result.Service = protocol
					if version := fingerprint.ExtractVersion(); version != "" {
						result.Version = version
					}
					return result
				}
			}
		}

		// Check Windows services if not identified by fingerprint
		if _, ok := windows.ServicePorts[port]; ok {
			if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
				result.Service = service
				result.Version = version
				return result
			}
		}

		// Check standard ports as fallback
		switch port {
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

		// Try to identify service from banner if not already identified
		if result.Service == "" && len(result.Banner) > 0 {
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

	if strings.Contains(bannerStr, "MySQL") {
		return "MySQL", ""
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

	ports := make(chan uint16, s.threads*2)
	fastScanResults := make(chan portScanResult, s.threads*2)

	var errorRate uint64
	totalPorts := uint64(s.endPort - s.startPort + 1)
	var scanned uint64

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

			time.Sleep(s.retryDelay) // Small delay between batches
			currentPort = batchEnd + 1
		}
		close(ports)
	}()

	// Process results with improved progress handling
	go func() {
		const progressUpdateInterval = time.Millisecond * 100
		lastUpdate := time.Now()
		lastPercentage := float64(0)

		for result := range fastScanResults {
			newScanned := atomic.AddUint64(&scanned, 1)
			now := time.Now()
			// Calculate current progress
			currentProgress := float64(newScanned) / float64(totalPorts) * 100
			// Update progress if enough time has passed or it's a significant change
			if now.Sub(lastUpdate) >= progressUpdateInterval ||
				currentProgress-lastPercentage >= 1.0 {
				s.updateProgress(currentProgress)
				lastUpdate = now
				lastPercentage = currentProgress
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
		s.updateProgress(100)
	}()

	wg.Wait()
	close(fastScanResults)

	// Ensure final progress update
	s.updateProgress(100)
	close(s.progress)

	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
