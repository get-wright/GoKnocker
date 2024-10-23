package scanner

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"GoKnocker/models"
	"GoKnocker/services"
)

type Scanner struct {
	host      string
	startPort uint16
	endPort   uint16
	timeout   time.Duration
	rateLimit time.Duration
	threads   int
	debug     bool
	results   chan models.PortResult
	progress  chan float64
}

func NewScanner() *Scanner {
	return &Scanner{
		startPort: 1,
		endPort:   65535,
		timeout:   time.Second * 3,
		rateLimit: time.Millisecond * 2,
		threads:   100,
		results:   make(chan models.PortResult),
		progress:  make(chan float64),
	}
}

func (s *Scanner) SetHost(host string) {
	s.host = host
}

func (s *Scanner) GetHost() string {
	return s.host
}

func (s *Scanner) SetStartPort(port uint16) {
	s.startPort = port
}

func (s *Scanner) GetStartPort() uint16 {
	return s.startPort
}

func (s *Scanner) SetEndPort(port uint16) {
	s.endPort = port
}

func (s *Scanner) GetEndPort() uint16 {
	return s.endPort
}

func (s *Scanner) SetRateLimit(rate time.Duration) {
	s.rateLimit = rate
}

func (s *Scanner) GetRateLimit() time.Duration {
	return s.rateLimit
}

func (s *Scanner) GetProgressChan() chan float64 {
	return s.progress
}

func (s *Scanner) scanPort(port uint16) models.PortResult {
	result := models.PortResult{
		IP:    net.ParseIP(s.host),
		Port:  port,
		State: "closed",
	}

	address := fmt.Sprintf("%s:%d", s.host, port)

	for _, network := range []string{"tcp4", "tcp6"} {
		start := time.Now()
		conn, err := net.DialTimeout(network, address, s.timeout)

		if err != nil {
			if strings.Contains(err.Error(), "refused") {
				result.State = "filtered"
			}
			continue
		}

		defer conn.Close()
		result.State = "open"
		result.ResponseTime = time.Since(start)

		switch port {
		case 22:
			service, version := services.TrySSH(address, s.timeout)
			if service != "" {
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
			// Updated HTTPS probing
			if baseInfo, enhancedInfo := services.ProbeHTTPS(s.host, port, s.timeout); baseInfo != nil {
				result.Service = "HTTPS"
				result.HttpInfo = baseInfo
				result.EnhancedInfo = enhancedInfo

				// Try to get server version from enhanced info
				if serverInfo, ok := enhancedInfo["server_info"].(services.ServerInfo); ok && serverInfo.Version != "" {
					result.Version = serverInfo.Version
				} else if baseInfo.Server != "" {
					result.Version = baseInfo.Server
				}
				return result
			}
		}

		// General banner grab for unknown services
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		banner := make([]byte, 1024)
		n, _ := conn.Read(banner)
		if n > 0 {
			result.Banner = bytes.TrimSpace(banner[:n])
			bannerStr := string(result.Banner)
			if strings.Contains(bannerStr, "SSH-") {
				result.Service = "SSH"
				parts := strings.SplitN(bannerStr, " ", 2)
				if len(parts) > 1 {
					result.Version = strings.TrimSpace(parts[1])
				}
			}
		}

		if result.State == "open" {
			return result
		}
	}

	return result
}

func (s *Scanner) Scan() []models.PortResult {
	var results []models.PortResult
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}
	rateLimiter := time.NewTicker(s.rateLimit)
	defer rateLimiter.Stop()

	ports := make(chan uint16, s.threads)
	totalPorts := s.endPort - s.startPort + 1
	scanned := uint64(0)

	// Worker pool
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				<-rateLimiter.C
				result := s.scanPort(port)
				if result.State == "open" {
					resultsMutex.Lock()
					results = append(results, result)
					resultsMutex.Unlock()
				}
				scanned++
				s.progress <- float64(scanned) / float64(totalPorts) * 100
			}
		}()
	}

	// Send ports to workers
	go func() {
		for port := s.startPort; port <= s.endPort; port++ {
			ports <- port
		}
		close(ports)
	}()

	wg.Wait()
	close(s.progress)

	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
