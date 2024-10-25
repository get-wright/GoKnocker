package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"GoKnocker/banner"
	"GoKnocker/models"
	"GoKnocker/scanner"
)

const (
	DEFAULT_THREADS = 500
	DEFAULT_TIMEOUT = 2
	DEFAULT_RATE    = 1000
	MIN_RATE        = 100
	MAX_RATE        = 2000
)

// main.go

func main() {
	banner.PrintBanner()

	scanner := scanner.NewScanner()
	reader := bufio.NewReader(os.Stdin)

	// Wait for user input before continuing
	reader.ReadString('\n')

	// Configure scanner...
	configureHost(scanner, reader)
	configurePortRange(scanner, reader)
	configureAdvancedOptions(scanner, reader)

	// Start the scan
	fmt.Printf("\nStarting scan of %s:\n", scanner.GetHost())
	fmt.Printf("- Port range: %d-%d\n", scanner.GetStartPort(), scanner.GetEndPort())
	fmt.Printf("- Scan rate: %.0f scans/second\n", float64(time.Second)/float64(scanner.GetRateLimit()))
	fmt.Println("\nProgress:")

	startTime := time.Now()

	// Start scanning in a goroutine
	resultsChan := make(chan []models.PortResult)
	go func() {
		resultsChan <- scanner.Scan()
	}()

	// Initialize progress display
	fmt.Print("\033[2K\r") // Clear line
	lastProgress := -1.0
	progressWidth := 40
	spinChars := []string{"|", "/", "-", "\\"}
	spinIndex := 0

	// Create a ticker for smooth animation
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// Progress display loop
	done := false
	for !done {
		select {
		case progress, ok := <-scanner.GetProgressChan():
			if !ok {
				done = true
				break
			}
			// Only update if significant change or completion
			if progress-lastProgress >= 0.1 || progress >= 100 {
				// Ensure progress doesn't exceed 100%
				if progress > 100 {
					progress = 100
				}
				fmt.Printf("\r%s %.1f%% %s",
					renderProgressBar(progress, progressWidth),
					progress,
					spinChars[spinIndex])
				lastProgress = progress
			}
		case <-ticker.C:
			// Update spinner even without progress change
			spinIndex = (spinIndex + 1) % len(spinChars)
			if lastProgress >= 0 {
				// Ensure lastProgress doesn't exceed 100%
				if lastProgress > 100 {
					lastProgress = 100
				}
				fmt.Printf("\r%s %.1f%% %s",
					renderProgressBar(lastProgress, progressWidth),
					lastProgress,
					spinChars[spinIndex])
			}
		}
	}
	fmt.Printf("\r%s 100.0%%\n\n", renderProgressBar(100.0, progressWidth))

	results := <-resultsChan
	duration := time.Since(startTime)

	// Print results...
	printResults(results, duration)
}

func renderProgressBar(progress float64, width int) string {
	// Ensure progress is between 0 and 100
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}

	// Calculate fill based on clamped progress
	fill := int((progress / 100) * float64(width))
	if fill < 0 {
		fill = 0
	}
	if fill > width {
		fill = width
	}

	empty := width - fill
	if empty < 0 {
		empty = 0
	}

	bar := "["
	bar += strings.Repeat("=", fill)
	if empty > 0 && fill < width {
		bar += ">"
		empty--
	}
	bar += strings.Repeat(" ", empty)
	bar += "]"

	return bar
}

func configureHost(s *scanner.Scanner, reader *bufio.Reader) {
	for {
		fmt.Print("Enter target host (e.g., localhost or example.com): ")
		host, _ := reader.ReadString('\n')
		s.SetHost(strings.TrimSpace(host))

		if s.GetHost() != "" {
			if ip := net.ParseIP(s.GetHost()); ip == nil {
				if addrs, err := net.LookupHost(s.GetHost()); err == nil {
					s.SetHost(addrs[0])
					fmt.Printf("Resolved to IP: %s\n", s.GetHost())
				} else {
					fmt.Printf("Error resolving host: %v\n", err)
					continue
				}
			}
			break
		}
	}
}

func configurePortRange(s *scanner.Scanner, reader *bufio.Reader) {
	// Start port
	fmt.Print("Enter start port (default 1): ")
	startStr, _ := reader.ReadString('\n')
	startStr = strings.TrimSpace(startStr)
	if start, err := strconv.Atoi(startStr); err == nil && start > 0 && start < 65536 {
		s.SetStartPort(uint16(start))
	}

	// End port
	fmt.Print("Enter end port (default 65535): ")
	endStr, _ := reader.ReadString('\n')
	endStr = strings.TrimSpace(endStr)
	if end, err := strconv.Atoi(endStr); err == nil && end > 0 && end < 65536 {
		s.SetEndPort(uint16(end))
	}

	// Validate port range
	if s.GetStartPort() > s.GetEndPort() {
		fmt.Println("Warning: Start port is greater than end port, swapping values.")
		start := s.GetStartPort()
		s.SetStartPort(s.GetEndPort())
		s.SetEndPort(start)
	}
}

func configureAdvancedOptions(s *scanner.Scanner, reader *bufio.Reader) {
	fmt.Println("\nAdvanced Options (press Enter to use defaults):")

	// Configure threads
	fmt.Printf("Enter number of concurrent threads (default %d): ", DEFAULT_THREADS)
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	if threads, err := strconv.Atoi(threadsStr); err == nil && threads > 0 {
		s.SetThreads(threads)
	}

	// Configure timeout
	fmt.Printf("Enter connection timeout in seconds (default %d): ", DEFAULT_TIMEOUT)
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
		s.SetTimeout(time.Duration(timeout) * time.Second)
	}

	// Configure scan rate
	fmt.Printf("Enter scan rate (scans per second, default %d, min %d, max %d): ", DEFAULT_RATE, MIN_RATE, MAX_RATE)
	rateStr, _ := reader.ReadString('\n')
	rateStr = strings.TrimSpace(rateStr)
	if rate, err := strconv.Atoi(rateStr); err == nil && rate >= MIN_RATE && rate <= MAX_RATE {
		s.SetRateLimit(time.Second / time.Duration(rate))
	}
	fmt.Println("\nCustom Port Mapping (press Enter to skip):")
	for {
		fmt.Print("Enter custom port mapping (format: port:service, e.g. 8022:SSH): ")
		mapping, _ := reader.ReadString('\n')
		mapping = strings.TrimSpace(mapping)

		if mapping == "" {
			break
		}

		parts := strings.Split(mapping, ":")
		if len(parts) != 2 {
			fmt.Println("Invalid format. Use port:service (e.g. 8022:SSH)")
			continue
		}

		port, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil || port == 0 || port > 65535 {
			fmt.Println("Invalid port number")
			continue
		}

		s.AddCustomPort(uint16(port), strings.TrimSpace(parts[1]))
		fmt.Printf("Added custom mapping: Port %d -> %s\n", port, parts[1])
	}
	fmt.Print("Enable debug output? (y/N): ")
	debugStr, _ := reader.ReadString('\n')
	debugStr = strings.TrimSpace(strings.ToLower(debugStr))
	if debugStr == "y" || debugStr == "yes" {
		s.SetDebug(true)
		fmt.Println("Debug output enabled")
	}
}

func printResults(results []models.PortResult, duration time.Duration) {
	fmt.Printf("\nScan completed in %v\n", duration)
	fmt.Printf("Found %d open ports:\n\n", len(results))

	if len(results) == 0 {
		fmt.Println("No open ports found")
		return
	}

	for _, result := range results {
		fmt.Printf("Port %d/tcp:\n", result.Port)
		fmt.Printf("  State: %s\n", result.State)
		if result.Service != "" {
			fmt.Printf("  Service: %s\n", result.Service)
			if result.Version != "" {
				fmt.Printf("  Version: %s\n", result.Version)
			}
		}

		if result.HttpInfo != nil {
			fmt.Printf("  HTTP Info:\n")
			fmt.Printf("    Status Code: %d\n", result.HttpInfo.StatusCode)
			if result.HttpInfo.Title != "" {
				fmt.Printf("    Title: %s\n", result.HttpInfo.Title)
			}
			if result.HttpInfo.Server != "" {
				fmt.Printf("    Server: %s\n", result.HttpInfo.Server)
			}
			if result.HttpInfo.PoweredBy != "" {
				fmt.Printf("    Powered By: %s\n", result.HttpInfo.PoweredBy)
			}
			if result.HttpInfo.ContentType != "" {
				fmt.Printf("    Content Type: %s\n", result.HttpInfo.ContentType)
			}
			if result.HttpInfo.Location != "" {
				fmt.Printf("    Redirect: %s\n", result.HttpInfo.Location)
			}

			// Enhanced HTTPS information
			if result.Service == "HTTPS" {
				if result.HttpInfo.TLSVersion != "" {
					fmt.Printf("    TLS Version: %s\n", result.HttpInfo.TLSVersion)
					fmt.Printf("    TLS Cipher: %s\n", result.HttpInfo.TLSCipher)
				}
				if result.HttpInfo.TLSCert != "" {
					fmt.Printf("    Certificate: %s\n", result.HttpInfo.TLSCert)
				}
			}
		}

		if len(result.Banner) > 0 {
			fmt.Printf("  Banner: %s\n", string(result.Banner))
		}
		fmt.Printf("  Response Time: %v\n\n", result.ResponseTime)
	}
}
