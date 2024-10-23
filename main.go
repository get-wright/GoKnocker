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
	"GoKnocker/services"
)

func main() {
	fmt.Println("=== GoKnocker ===")
	fmt.Println("Knock Knock! Any ports open?")
	fmt.Println()

	scanner := scanner.NewScanner()

	// Get host
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter target host (e.g., localhost or example.com): ")
		host, _ := reader.ReadString('\n')
		scanner.SetHost(strings.TrimSpace(host))

		if scanner.GetHost() != "" {
			if ip := net.ParseIP(scanner.GetHost()); ip == nil {
				if addrs, err := net.LookupHost(scanner.GetHost()); err == nil {
					scanner.SetHost(addrs[0])
				} else {
					fmt.Printf("Error resolving host: %v\n", err)
					continue
				}
			}
			break
		}
	}

	// Get port range
	fmt.Print("Enter start port (default 1): ")
	startStr, _ := reader.ReadString('\n')
	startStr = strings.TrimSpace(startStr)
	if start, err := strconv.Atoi(startStr); err == nil && start > 0 && start < 65536 {
		scanner.SetStartPort(uint16(start))
	}

	fmt.Print("Enter end port (default 65535): ")
	endStr, _ := reader.ReadString('\n')
	endStr = strings.TrimSpace(endStr)
	if end, err := strconv.Atoi(endStr); err == nil && end > 0 && end < 65536 {
		scanner.SetEndPort(uint16(end))
	}

	// Get scan rate
	fmt.Print("Enter scan rate (scans per second, default 500): ")
	rateStr, _ := reader.ReadString('\n')
	rateStr = strings.TrimSpace(rateStr)
	if rate, err := strconv.Atoi(rateStr); err == nil && rate > 0 {
		scanner.SetRateLimit(time.Second / time.Duration(rate))
	}

	fmt.Printf("\nStarting scan of %s with rate limit of %.0f scans/second\n",
		scanner.GetHost(), float64(time.Second)/float64(scanner.GetRateLimit()))

	startTime := time.Now()

	// Start scanning in a goroutine
	resultsChan := make(chan []models.PortResult)
	go func() {
		resultsChan <- scanner.Scan()
	}()

	fmt.Println("\nProgress:")
	for progress := range scanner.GetProgressChan() {
		fmt.Printf("\r[%s%s] %.1f%% ",
			strings.Repeat("=", int(progress/2.5)),
			strings.Repeat(" ", 40-int(progress/2.5)),
			progress)
	}
	fmt.Println("\n")

	results := <-resultsChan
	duration := time.Since(startTime)

	// Print results
	fmt.Printf("Scan completed in %v\n", duration)
	fmt.Printf("Found %d open ports:\n\n", len(results))

	if len(results) == 0 {
		fmt.Println("No open ports found")
	} else {
		for _, result := range results {
			fmt.Printf("Port %d/%s:\n", result.Port, "tcp")
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
				if result.Service == "HTTPS" && result.EnhancedInfo != nil {
					// Print supported HTTP methods
					if methods, ok := result.EnhancedInfo["methods"].([]string); ok && len(methods) > 0 {
						fmt.Printf("    Supported Methods: %s\n", strings.Join(methods, ", "))
					}

					// Print security headers
					if secHeaders, ok := result.EnhancedInfo["security_headers"].(map[string]string); ok && len(secHeaders) > 0 {
						fmt.Printf("    Security Headers:\n")
						for header, value := range secHeaders {
							fmt.Printf("      %s: %s\n", header, value)
						}
					}

					// Print TLS information
					if result.HttpInfo.TLSVersion != "" {
						fmt.Printf("    TLS Info:\n")
						fmt.Printf("      Version: %s\n", result.HttpInfo.TLSVersion)
						fmt.Printf("      Cipher: %s\n", result.HttpInfo.TLSCipher)

						if fingerprint, ok := result.EnhancedInfo["tls_fingerprint"].(string); ok {
							fmt.Printf("      Fingerprint: %s\n", fingerprint)
						}
					}

					// Print certificate chain information
					if certChain, ok := result.EnhancedInfo["certificate_chain"].([]services.CertInfo); ok && len(certChain) > 0 {
						fmt.Printf("    Certificate Chain:\n")
						for i, cert := range certChain {
							fmt.Printf("      Certificate %d:\n", i+1)
							fmt.Printf("        Subject: %s\n", cert.Subject)
							fmt.Printf("        Issuer: %s\n", cert.Issuer)
							fmt.Printf("        Valid From: %s\n", cert.ValidFrom.Format("2006-01-02"))
							fmt.Printf("        Valid To: %s\n", cert.ValidTo.Format("2006-01-02"))
							if len(cert.SubjectAltNames) > 0 {
								fmt.Printf("        Subject Alternative Names:\n")
								for _, san := range cert.SubjectAltNames {
									fmt.Printf("          - %s\n", san)
								}
							}
						}
					}

					// Print server information
					if serverInfo, ok := result.EnhancedInfo["server_info"].(services.ServerInfo); ok {
						if serverInfo.Technology != "" {
							fmt.Printf("    Technology Stack: %s\n", serverInfo.Technology)
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
}
