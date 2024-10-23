package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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

func main() {
	printBanner()

	scanner := scanner.NewScanner()
	reader := bufio.NewReader(os.Stdin)

	// Get and validate host
	configureHost(scanner, reader)

	// Configure port range
	configurePortRange(scanner, reader)

	// Configure advanced options
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

	// Show progress bar
	for progress := range scanner.GetProgressChan() {
		fmt.Printf("\r[%s%s] %.1f%% ",
			strings.Repeat("=", int(progress/2.5)),
			strings.Repeat(" ", 40-int(progress/2.5)),
			progress)
	}

	results := <-resultsChan
	duration := time.Since(startTime)

	// Print results
	printResults(results, duration)
}

func printBanner() {
	fmt.Println("=== GoKnocker ===")
	fmt.Println("Knock Knock! Any ports open?")
	fmt.Println()
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
}

func printResults(results []models.PortResult, duration time.Duration) {
	fmt.Printf("Scan completed in %v\n", duration)
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
