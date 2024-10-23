package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
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
)

var (
	mutex    sync.Mutex
	scanning = true
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
	}
}

func printBanner() {
	fmt.Println("=== GoKnocker ===")
	fmt.Println("Knock Knock! Any ports open?")
	fmt.Println()
}

func configureHost(s *scanner.Scanner, reader *bufio.Reader) {
	for {
		fmt.Print("Enter target host (e.g., localhost or example.com): ")
		host, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		host = strings.TrimSpace(host)
		s.SetHost(host)

		if s.GetHost() != "" {
			if ip := net.ParseIP(s.GetHost()); ip == nil {
				fmt.Printf("Resolving hostname %s...\n", s.GetHost())
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
	for {
		fmt.Print("Enter start port (default 1): ")
		startStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		startStr = strings.TrimSpace(startStr)
		if startStr == "" {
			break
		}

		start, err := strconv.Atoi(startStr)
		if err != nil || start < 1 || start > 65535 {
			fmt.Println("Invalid port number. Please enter a number between 1 and 65535.")
			continue
		}
		s.SetStartPort(uint16(start))
		break
	}

	// End port
	for {
		fmt.Print("Enter end port (default 65535): ")
		endStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		endStr = strings.TrimSpace(endStr)
		if endStr == "" {
			break
		}

		end, err := strconv.Atoi(endStr)
		if err != nil || end < 1 || end > 65535 {
			fmt.Println("Invalid port number. Please enter a number between 1 and 65535.")
			continue
		}
		s.SetEndPort(uint16(end))
		break
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
	for {
		fmt.Printf("Enter number of concurrent threads (default %d): ", DEFAULT_THREADS)
		threadsStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		threadsStr = strings.TrimSpace(threadsStr)
		if threadsStr == "" {
			break
		}

		threads, err := strconv.Atoi(threadsStr)
		if err != nil || threads < 1 {
			fmt.Println("Invalid thread count. Please enter a positive number.")
			continue
		}
		s.SetThreads(threads)
		break
	}

	// Configure timeout
	for {
		fmt.Printf("Enter connection timeout in seconds (default %d): ", DEFAULT_TIMEOUT)
		timeoutStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		timeoutStr = strings.TrimSpace(timeoutStr)
		if timeoutStr == "" {
			break
		}

		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil || timeout < 1 {
			fmt.Println("Invalid timeout. Please enter a positive number.")
			continue
		}
		s.SetTimeout(time.Duration(timeout) * time.Second)
		break
	}

	// Configure scan rate
	for {
		fmt.Printf("Enter scan rate (scans per second, default %d, min %d, max %d): ", DEFAULT_RATE, MIN_RATE, MAX_RATE)
		rateStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		rateStr = strings.TrimSpace(rateStr)
		if rateStr == "" {
			break
		}

		rate, err := strconv.Atoi(rateStr)
		if err != nil || rate < MIN_RATE || rate > MAX_RATE {
			fmt.Printf("Invalid rate. Please enter a number between %d and %d.\n", MIN_RATE, MAX_RATE)
			continue
		}
		s.SetRateLimit(time.Second / time.Duration(rate))
		break
	}
}

func showProgress(progressChan chan float64) {
	const progressWidth = 40
	lastProgress := 0.0
	fmt.Printf("\r[%s] 0.0%%", strings.Repeat(" ", progressWidth))

	for progress := range progressChan {
		// Ensure progress never goes backwards
		if progress < lastProgress {
			progress = lastProgress
		}
		lastProgress = progress

		// Calculate the number of blocks to display
		blocks := int(progress / (100.0 / float64(progressWidth)))
		if blocks > progressWidth {
			blocks = progressWidth
		}
		bar := strings.Repeat("=", blocks) + strings.Repeat(" ", progressWidth-blocks)

		// Print the progress bar with carriage return
		fmt.Printf("\r[%s] %.1f%%", bar, progress)
	}
	fmt.Println()
}

func startScan(s *scanner.Scanner, sigChan chan os.Signal) []models.PortResult {
	fmt.Printf("\nStarting scan of %s:\n", s.GetHost())
	fmt.Printf("- Port range: %d-%d\n", s.GetStartPort(), s.GetEndPort())
	fmt.Printf("- Scan rate: %.0f scans/second\n", float64(time.Second)/float64(s.GetRateLimit()))
	fmt.Println("\nProgress:")

	startTime := time.Now()

	// Start scanning in a goroutine
	resultsChan := make(chan []models.PortResult, 1)
	go func() {
		resultsChan <- s.Scan()
	}()

	// Create a done channel for progress monitoring
	progressDone := make(chan struct{})

	// Start progress monitoring in a separate goroutine
	go func() {
		showProgress(s.GetProgressChan())
		close(progressDone)
	}()

	// Wait for either scan completion or interrupt
	select {
	case results := <-resultsChan:
		duration := time.Since(startTime)
		<-progressDone
		fmt.Printf("\nScan completed in %v\n", duration)
		return results

	case <-sigChan:
		fmt.Printf("\nReceived interrupt signal. Shutting down...\n")
		<-progressDone
		return nil
	}
}

func printResults(results []models.PortResult) {
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
					fmt.Printf("    TLS Info:\n")
					fmt.Printf("      Version: %s\n", result.HttpInfo.TLSVersion)
					fmt.Printf("      Cipher: %s\n", result.HttpInfo.TLSCipher)
					if result.HttpInfo.TLSCert != "" {
						fmt.Printf("      Certificate: %s\n", result.HttpInfo.TLSCert)
					}
				}
			}
		}

		if len(result.Banner) > 0 {
			fmt.Printf("  Banner: %s\n", string(result.Banner))
		}

		fmt.Printf("  Response Time: %v\n\n", result.ResponseTime)
	}
}
