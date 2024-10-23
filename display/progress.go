package display

import (
	"fmt"
	"os"
	"strings"
	"time"

	"GoKnocker/stats"

	"github.com/mattn/go-isatty"
)

// ProgressDisplay handles the display of progress and statistics
type ProgressDisplay struct {
	stats         *stats.ScanStats
	width         int
	isTerminal    bool
	lastUpdate    time.Time
	updateMinWait time.Duration
}

// NewProgressDisplay creates a new progress display handler
func NewProgressDisplay(stats *stats.ScanStats) *ProgressDisplay {
	width := 80
	isTerminal := isatty.IsTerminal(os.Stdout.Fd())

	return &ProgressDisplay{
		stats:         stats,
		width:         width,
		isTerminal:    isTerminal,
		updateMinWait: time.Millisecond * 100, // Minimum time between updates
	}
}

// Start begins the progress display loop
func (p *ProgressDisplay) Start() {
	if !p.isTerminal {
		return
	}

	// Hide cursor
	fmt.Print("\033[?25l")

	ticker := time.NewTicker(p.updateMinWait)
	defer ticker.Stop()

	for range ticker.C {
		p.update()
		if p.stats.IsComplete() {
			break
		}
	}

	// Show cursor and add final newline
	fmt.Print("\033[?25h\n")
}

// update refreshes the display
func (p *ProgressDisplay) update() {
	if time.Since(p.lastUpdate) < p.updateMinWait {
		return
	}

	// Clear previous lines if detailed stats enabled
	if p.stats.IsDetailedEnabled() {
		fmt.Print(strings.Repeat("\033[2K\033[1A", 7))
	}
	fmt.Print("\033[2K\r")

	// Update display
	fmt.Print(p.stats.FormatProgressBar(p.width))
	p.lastUpdate = time.Now()
}

// Stop cleans up the display
func (p *ProgressDisplay) Stop() {
	if !p.isTerminal {
		return
	}

	// Ensure cursor is shown
	fmt.Print("\033[?25h")
}
