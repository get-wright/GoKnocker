// banner/banner.go
package banner

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

const bannerArt = `
   ______      __ __                  __            
  / ____/___  / //_/___  ____  _____/ /_____  _____
 / / __/ __ \/ ,< / __ \/ __ \/ ___/ //_/ _ \/ ___/
/ /_/ / /_/ / /| / /_/ / /_/ / /__/ ,< /  __/ /    
\____/\____/_/ |_\____/\____/\___/_/|_|\___/_/     
                                                    
`

const colorReset = "\033[0m"
const colorCyan = "\033[36m"
const colorYellow = "\033[33m"
const colorGreen = "\033[32m"

func PrintBanner() {
	// Clear screen first
	fmt.Print("\033[H\033[2J")

	// Print the main banner in cyan
	if runtime.GOOS != "windows" {
		fmt.Print(colorCyan)
	}
	fmt.Println(bannerArt)
	fmt.Println("Knock Knock... Any port open?!?")

	if runtime.GOOS != "windows" {
		fmt.Print(colorReset)
	}

	// Print tagline with animation
	tagline := "[ Port Scanner & Service Detector ]"
	if runtime.GOOS != "windows" {
		fmt.Print(colorYellow)
	}

	for _, char := range tagline {
		fmt.Print(string(char))
		time.Sleep(30 * time.Millisecond)
	}

	if runtime.GOOS != "windows" {
		fmt.Print(colorReset)
	}
	fmt.Println()

	// Print version and info
	if runtime.GOOS != "windows" {
		fmt.Print(colorGreen)
	}

	info := []string{
		"Version: 1.0.0",
		"Author: n3m0",
		"License: MIT",
		fmt.Sprintf("Go Version: %s", runtime.Version()),
	}

	// Find the longest line for proper box sizing
	maxLength := 0
	for _, line := range info {
		if len(line) > maxLength {
			maxLength = len(line)
		}
	}

	// Print top border
	fmt.Print("┌")
	fmt.Print(strings.Repeat("─", maxLength+2))
	fmt.Println("┐")

	// Print info lines with proper padding
	for _, line := range info {
		padding := strings.Repeat(" ", maxLength-len(line))
		fmt.Printf("│ %s%s │\n", line, padding)
	}

	// Print bottom border
	fmt.Print("└")
	fmt.Print(strings.Repeat("─", maxLength+2))
	fmt.Println("┘")

	if runtime.GOOS != "windows" {
		fmt.Print(colorReset)
	}

	// Add some spacing
	fmt.Println("\nType 'Ctrl + C' to exit.")
	fmt.Println("Press Enter to continue...")
	fmt.Println()
}
