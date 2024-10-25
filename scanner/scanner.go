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
	portsScanned      int64
	totalPorts        int64
	progressMutex     sync.Mutex
}

func NewScanner() *Scanner {
	s := &Scanner{
		startPort:    1,
		endPort:      65535,
		timeout:      time.Second * 2,
		rateLimit:    time.Millisecond,
		threads:      500,
		maxRetries:   2,
		adjustRate:   true,
		minRateLimit: time.Microsecond * 500,
		maxRateLimit: time.Millisecond * 5,
		results:      make(chan models.PortResult),
		progress:     make(chan float64, 100),
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
	s.debug = enabled
	s.debugLogger = NewDebugLogger(enabled)
}

func (s *Scanner) updateProgress() {
	scanned := atomic.LoadInt64(&s.portsScanned)
	progress := (float64(scanned) / float64(s.totalPorts)) * 100

	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}

	s.progressMutex.Lock()
	defer s.progressMutex.Unlock()

	select {
	case s.progress <- progress:
		if s.debug {
			s.debugLogger.Log("Progress updated: %.2f%% (%d/%d ports)", progress, scanned, s.totalPorts)
		}
	default:
	}
}

type portScanResult struct {
	port     uint16
	isOpen   bool
	response time.Duration
}

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

			if s.debug {
				s.debugLogger.Log("Attempting connection to %s", address)
			}

			conn, err := dialer.DialContext(ctx, "tcp", address)
			duration := time.Since(start)

			atomic.AddInt64(&s.portsScanned, 1)
			s.updateProgress()

			if err == nil {
				conn.Close()
				if s.debug {
					s.debugLogger.Log("Port %d is open (took %v)", port, duration)
				}
				results <- portScanResult{
					port:     port,
					isOpen:   true,
					response: duration,
				}
			} else {
				if s.debug {
					s.debugLogger.Log("Port %d is closed/filtered: %v", port, err)
				}
				if !strings.Contains(err.Error(), "refused") {
					atomic.AddUint64(errorRate, 1)
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

func (s *Scanner) validatePort(port uint16, initialResponse time.Duration) models.PortResult {
	if s.debug {
		s.debugLogger.Log("Validating port %d (initial response: %v)", port, initialResponse)
	}

	result := models.PortResult{
		IP:           net.ParseIP(s.host),
		Port:         port,
		State:        "closed",
		ResponseTime: initialResponse,
	}

	switch port {
	case 80, 8080, 8000, 5000, 3000:
		if s.debug {
			s.debugLogger.Log("Attempting HTTP probe on port %d", port)
		}
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
		if s.debug {
			s.debugLogger.Log("Attempting HTTPS probe on port %d", port)
		}
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
		if s.debug {
			s.debugLogger.Log("Attempting SSH probe on port %d", port)
		}
		if service, version := services.TrySSH(fmt.Sprintf("%s:%d", s.host, port), s.timeout); service != "" {
			result.Service = service
			result.Version = version
			result.State = "open"
			return result
		}
	}

	if expectedService, ok := s.customPorts[port]; ok {
		if s.debug {
			s.debugLogger.Log("Port %d has custom mapping to service: %s", port, expectedService)
		}
		if service, version := s.serviceIdentifier.IdentifyService(s.host, port); service != "" {
			if s.debug {
				s.debugLogger.Log("Service detected on port %d: %s (version: %s)", port, service, version)
			}
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

	if _, ok := windows.ServicePorts[port]; ok {
		if s.debug {
			s.debugLogger.Log("Attempting Windows service detection on port %d", port)
		}
		if service, version := windows.ProbeService(s.host, port, s.timeout); service != "" {
			if s.debug {
				s.debugLogger.Log("Windows service detected on port %d: %s (version: %s)", port, service, version)
			}
			result.Service = service
			result.Version = version
			result.State = "open"
			return result
		}
	}

	if service, version := s.serviceIdentifier.IdentifyService(s.host, port); service != "" {
		if s.debug {
			s.debugLogger.Log("Fingerprint detected on port %d: %s (version: %s)", port, service, version)
		}
		result.Service = service
		result.Version = version
		result.State = "open"
		return result
	}

	address := fmt.Sprintf("%s:%d", s.host, port)
	if s.debug {
		s.debugLogger.Log("Attempting banner grab on port %d", port)
	}

	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		if s.debug {
			s.debugLogger.LogError(port, err)
		}
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
	if err != nil && s.debug {
		s.debugLogger.LogError(port, err)
	}
	if n > 0 {
		result.Banner = bytes.TrimSpace(banner[:n])
		if s.debug {
			s.debugLogger.LogBanner(port, result.Banner)
		}
	}

	return result
}

func (s *Scanner) Scan() []models.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	s.portsScanned = 0
	s.totalPorts = int64(s.endPort - s.startPort + 1)

	if s.totalPorts <= 0 {
		s.totalPorts = 1
	}

	ports := make(chan uint16, s.threads*2)
	fastScanResults := make(chan portScanResult, s.threads*2)

	var errorRate uint64

	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.fastPortScan(ctx, ports, fastScanResults, &errorRate)
		}()
	}

	go func() {
		defer close(ports)
		isDefaultScan := s.startPort == 1 && s.endPort == 65535

		for port := s.startPort; port <= s.endPort; port++ {
			select {
			case ports <- port:
				if isDefaultScan && port == 65535 {
					if s.debug {
						s.debugLogger.Log("Reached port 65535 in default scan, initiating cleanup")
					}
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

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

	select {
	case s.progress <- 100.0:
	default:
	}
	close(s.progress)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
