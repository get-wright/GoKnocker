package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"GoKnocker/models"
	"GoKnocker/scanner"

	"github.com/mattn/go-isatty"
)

const (
	DEFAULT_THREADS = 500
	DEFAULT_TIMEOUT = 2
	DEFAULT_RATE    = 1000
	MIN_RATE        = 100
	MAX_RATE        = 2000
	VERSION         = "2.0.0"
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
	fmt.Printf(`
╔═══════════════════════════════════════╗
║             GoKnocker v%s           ║
║      Port Scanner and Service Probe   ║
╚═══════════════════════════════════════╝

`, VERSION)
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
		if host == "" {
			continue
		}

		s.SetHost(host)

		// Validate and resolve hostname
		if ip := net.ParseIP(host); ip == nil {
			fmt.Printf("Resolving hostname %s...\n", host)
			addrs, err := net.LookupHost(host)
			if err != nil {
				fmt.Printf("Error resolving host: %v\n", err)
				continue
			}
			s.SetHost(addrs[0])
			fmt.Printf("Resolved to IP: %s\n", s.GetHost())
		}
		break
	}
}

func configurePortRange(s *scanner.Scanner, reader *bufio.Reader) {
	// Start port configuration
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

	// End port configuration
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

	// Validate and swap if necessary
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

	// Configure detailed statistics
	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Print("Enable detailed statistics display? (y/N): ")
		detailedStr, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(detailedStr)) == "y" {
			s.EnableDetailedStats(true)
		}
	}
}

func startScan(s *scanner.Scanner, sigChan chan os.Signal) []models.PortResult {
	// Print scan configuration
	fmt.Printf("\nScan Configuration:")
	fmt.Printf("\n• Target: %s", s.GetHost())
	fmt.Printf("\n• Port range: %d-%d", s.GetStartPort(), s.GetEndPort())
	fmt.Printf("\n• Scan rate: %.0f scans/second", float64(time.Second)/float64(s.GetRateLimit()))
	fmt.Println("\n\nStarting scan...")

	// Start scanning in a goroutine
	resultsChan := make(chan []models.PortResult, 1)
	go func() {
		resultsChan <- s.Scan()
	}()

	// Wait for either scan completion or interrupt
	select {
	case results := <-resultsChan:
		return results

	case <-sigChan:
		fmt.Printf("\nReceived interrupt signal. Shutting down gracefully...\n")
		return nil
	}
}

func printResults(results []models.PortResult) {
	if len(results) == 0 {
		fmt.Println("\nNo open ports found")
		return
	}

	fmt.Printf("\nScan Results: %d open ports found\n", len(results))
	fmt.Println("════════════════════════════════════════════")

	for _, result := range results {
		fmt.Printf("\nPort %d/tcp\n", result.Port)
		fmt.Printf("  State: %s\n", result.State)

		if result.Service != "" {
			fmt.Printf("  Service: %s\n", result.Service)
			if result.Version != "" {
				fmt.Printf("  Version: %s\n", result.Version)
			}
		}

		if result.HttpInfo != nil {
			fmt.Printf("  HTTP Information:\n")
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

			if result.Service == "HTTPS" {
				if result.HttpInfo.TLSVersion != "" {
					fmt.Printf("    TLS Information:\n")
					fmt.Printf("      Version: %s\n", result.HttpInfo.TLSVersion)
					fmt.Printf("      Cipher: %s\n", result.HttpInfo.TLSCipher)
					if result.HttpInfo.TLSCert != "" {
						fmt.Printf("      Certificate: %s\n", result.HttpInfo.TLSCert)
					}
				}

				if result.EnhancedInfo != nil {
					if secHeaders, ok := result.EnhancedInfo["security_headers"].(map[string]string); ok && len(secHeaders) > 0 {
						fmt.Printf("    Security Headers:\n")
						for header, value := range secHeaders {
							fmt.Printf("      %s: %s\n", header, value)
						}
					}
				}
			}
		}

		if len(result.Banner) > 0 {
			fmt.Printf("  Banner: %s\n", string(result.Banner))
		}

		fmt.Printf("  Response Time: %v\n", result.ResponseTime)
	}

	fmt.Println("\n════════════════════════════════════════════")
}
