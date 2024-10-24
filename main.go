package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	VERSION         = "1.1.0"
)

func main() {
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	printBanner()

	scanner := scanner.NewScanner()
	reader := bufio.NewReader(os.Stdin)

	// Get and validate host
	configureHost(scanner, reader)

	// Configure port range
	configurePortRange(scanner, reader)

	// Configure advanced options
	configureAdvancedOptions(scanner, reader)

	results := startScan(scanner, sigChan)

	if results != nil {
		printResults(results)
		printSummary(results)
	}
}

func printBanner() {
	fmt.Printf("\033[1;34m") // Blue text
	fmt.Println(`
   ______      ____                      __            
  / ____/___  / / /_____  ____  _______/ /_____  _____
 / / __/ __ \/ / //_/ _ \/ __ \/ ___/ //_/ _ \/ ___/
/ /_/ / /_/ / / ,< /  __/ / / / /__/ ,< /  __/ /    
\____/\____/_/_/|_|\___/_/ /_/\___/_/|_|\___/_/     
                                         
`, VERSION)
	fmt.Printf("\033[0m") // Reset color
	fmt.Println("\nFast and Feature-rich Port Scanner written in Go")
	fmt.Printf("Running on %s %s (%s)\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Println("Press Ctrl+C at any time to stop the scan")
	fmt.Println()
}

func configureHost(s *scanner.Scanner, reader *bufio.Reader) {
	for {
		fmt.Print("\033[1m[*] Enter target host\033[0m (e.g., localhost or example.com): ")
		host, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		host = strings.TrimSpace(host)
		s.SetHost(host)

		if s.GetHost() != "" {
			if ip := net.ParseIP(s.GetHost()); ip == nil {
				fmt.Printf("\033[33mResolving hostname %s...\033[0m\n", s.GetHost())
				if addrs, err := net.LookupHost(s.GetHost()); err == nil {
					s.SetHost(addrs[0])
					fmt.Printf("\033[32mResolved to IP: %s\033[0m\n", s.GetHost())
				} else {
					fmt.Printf("\033[31mError resolving host: %v\033[0m\n", err)
					continue
				}
			}
			break
		}
	}
}

func configurePortRange(s *scanner.Scanner, reader *bufio.Reader) {
	// Start port
	for {
		fmt.Print("\033[1m[*] Enter start port\033[0m (default 1): ")
		startStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		startStr = strings.TrimSpace(startStr)
		if startStr == "" {
			break
		}

		start, err := strconv.Atoi(startStr)
		if err != nil || start < 1 || start > 65535 {
			fmt.Println("\033[31mInvalid port number. Please enter a number between 1 and 65535.\033[0m")
			continue
		}
		s.SetStartPort(uint16(start))
		break
	}

	// End port
	for {
		fmt.Print("\033[1m[*] Enter end port\033[0m (default 65535): ")
		endStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		endStr = strings.TrimSpace(endStr)
		if endStr == "" {
			break
		}

		end, err := strconv.Atoi(endStr)
		if err != nil || end < 1 || end > 65535 {
			fmt.Println("\033[31mInvalid port number. Please enter a number between 1 and 65535.\033[0m")
			continue
		}
		s.SetEndPort(uint16(end))
		break
	}

	// Validate port range
	if s.GetStartPort() > s.GetEndPort() {
		fmt.Println("\033[33mWarning: Start port is greater than end port, swapping values.\033[0m")
		start := s.GetStartPort()
		s.SetStartPort(s.GetEndPort())
		s.SetEndPort(start)
	}
}

func configureAdvancedOptions(s *scanner.Scanner, reader *bufio.Reader) {
	fmt.Println("\n\033[1mAdvanced Options\033[0m (press Enter to use defaults):")

	// Configure threads
	for {
		fmt.Printf("\033[1m[*] Enter number of concurrent threads\033[0m (default %d): ", DEFAULT_THREADS)
		threadsStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		threadsStr = strings.TrimSpace(threadsStr)
		if threadsStr == "" {
			break
		}

		threads, err := strconv.Atoi(threadsStr)
		if err != nil || threads < 1 {
			fmt.Println("\033[31mInvalid thread count. Please enter a positive number.\033[0m")
			continue
		}
		s.SetThreads(threads)
		break
	}

	// Configure timeout
	for {
		fmt.Printf("\033[1m[*] Enter connection timeout in seconds\033[0m (default %d): ", DEFAULT_TIMEOUT)
		timeoutStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		timeoutStr = strings.TrimSpace(timeoutStr)
		if timeoutStr == "" {
			break
		}

		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil || timeout < 1 {
			fmt.Println("\033[31mInvalid timeout. Please enter a positive number.\033[0m")
			continue
		}
		s.SetTimeout(time.Duration(timeout) * time.Second)
		break
	}

	// Configure scan rate
	for {
		fmt.Printf("\033[1m[*] Enter scan rate\033[0m (scans per second, default %d, min %d, max %d): ",
			DEFAULT_RATE, MIN_RATE, MAX_RATE)
		rateStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("\033[31mError reading input: %v\033[0m\n", err)
			continue
		}

		rateStr = strings.TrimSpace(rateStr)
		if rateStr == "" {
			break
		}

		rate, err := strconv.Atoi(rateStr)
		if err != nil || rate < MIN_RATE || rate > MAX_RATE {
			fmt.Printf("\033[31mInvalid rate. Please enter a number between %d and %d.\033[0m\n",
				MIN_RATE, MAX_RATE)
			continue
		}
		s.SetRateLimit(time.Second / time.Duration(rate))
		break
	}
}

func startScan(s *scanner.Scanner, sigChan chan os.Signal) []models.PortResult {
	fmt.Println("\n\033[1mScan Configuration:\033[0m")
	fmt.Printf("Target: \033[1;32m%s\033[0m\n", s.GetHost())
	fmt.Printf("Port Range: \033[1;32m%d-%d\033[0m\n", s.GetStartPort(), s.GetEndPort())
	fmt.Printf("Threads: \033[1;32m%d\033[0m\n", s.GetThreads())
	fmt.Printf("Timeout: \033[1;32m%v\033[0m\n", s.GetTimeout())
	fmt.Printf("Scan Rate: \033[1;32m%.0f\033[0m scans/second\n",
		float64(time.Second)/float64(s.GetRateLimit()))

	fmt.Println("\n\033[1mStarting scan...\033[0m")
	// Add empty lines for statistics display
	fmt.Println(strings.Repeat("\n", 15))

	startTime := time.Now()

	// Start scanning in a goroutine
	resultsChan := make(chan []models.PortResult, 1)
	go func() {
		resultsChan <- s.Scan()
	}()

	// Wait for either scan completion or interrupt
	select {
	case results := <-resultsChan:
		duration := time.Since(startTime)
		fmt.Printf("\n\033[1;32mScan completed in %v\033[0m\n", duration)
		fmt.Printf("Scanned port range: %d-%d\n", s.GetStartPort(), s.GetEndPort())
		return results

	case <-sigChan:
		fmt.Printf("\n\033[1;31mReceived interrupt signal. Shutting down...\033[0m\n")
		return nil
	}
}

func printResults(results []models.PortResult) {
	fmt.Printf("\n\033[1mScan Results:\033[0m\n")
	fmt.Printf("Found \033[1;32m%d\033[0m open ports\n\n", len(results))

	if len(results) == 0 {
		fmt.Println("\033[33mNo open ports found\033[0m")
		return
	}

	// Print results in a table format
	fmt.Println("\033[1mPORT      STATE    SERVICE    VERSION    RESPONSE TIME\033[0m")
	fmt.Println(strings.Repeat("-", 70))

	for _, result := range results {
		// Basic port information
		fmt.Printf("%-9d %-8s %-10s %-10s %v\n",
			result.Port,
			formatState(result.State),
			formatService(result.Service),
			truncateString(result.Version, 10),
			result.ResponseTime)

		// HTTP Information
		if result.HttpInfo != nil {
			fmt.Printf("└─ HTTP Info:\n")
			fmt.Printf("   ├─ Status: %d\n", result.HttpInfo.StatusCode)
			if result.HttpInfo.Title != "" {
				fmt.Printf("   ├─ Title: %s\n", result.HttpInfo.Title)
			}
			if result.HttpInfo.Server != "" {
				fmt.Printf("   ├─ Server: %s\n", result.HttpInfo.Server)
			}
			if result.HttpInfo.PoweredBy != "" {
				fmt.Printf("   ├─ Powered By: %s\n", result.HttpInfo.PoweredBy)
			}

			// TLS Information for HTTPS
			if result.Service == "HTTPS" && result.HttpInfo.TLSVersion != "" {
				fmt.Printf("   └─ TLS Info:\n")
				fmt.Printf("      ├─ Version: %s\n", result.HttpInfo.TLSVersion)
				fmt.Printf("      ├─ Cipher: %s\n", result.HttpInfo.TLSCipher)
				if result.HttpInfo.TLSCert != "" {
					fmt.Printf("      └─ Certificate: %s\n", result.HttpInfo.TLSCert)
				}
			}
		}

		// Print banner if available
		if len(result.Banner) > 0 {
			fmt.Printf("└─ Banner: %s\n", formatBanner(string(result.Banner)))
		}

		fmt.Println()
	}
}

func printSummary(results []models.PortResult) {
	// Count services
	services := make(map[string]int)
	var totalResponseTime time.Duration

	for _, result := range results {
		if result.Service != "" {
			services[result.Service]++
		}
		totalResponseTime += result.ResponseTime
	}

	fmt.Printf("\n\033[1mScan Summary:\033[0m\n")
	// Calculate total ports from the results
	fmt.Printf("Total Ports Found: \033[1;32m%d\033[0m\n", len(results))

	if len(results) > 0 {
		fmt.Printf("Average Response Time: \033[1;32m%v\033[0m\n",
			totalResponseTime/time.Duration(len(results)))

		fmt.Println("\n\033[1mService Distribution:\033[0m")
		for service, count := range services {
			fmt.Printf("%-15s: \033[1;32m%d\033[0m\n", service, count)
		}
	}
}

// Helper functions
func formatState(state string) string {
	switch state {
	case "open":
		return "\033[1;32m" + state + "\033[0m"
	case "filtered":
		return "\033[1;33m" + state + "\033[0m"
	default:
		return "\033[1;31m" + state + "\033[0m"
	}
}

func formatService(service string) string {
	if service == "" {
		return "\033[1;30munknown\033[0m"
	}
	return service
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func formatBanner(banner string) string {
	// Remove non-printable characters and trim spaces
	banner = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, banner)
	return strings.TrimSpace(banner)
}
