package utils

import (
	"strings"
)

func ExtractTitle(body string) string {
	lower := strings.ToLower(body)
	titleStart := strings.Index(lower, "<title>")
	if titleStart == -1 {
		return ""
	}
	titleStart += 7

	titleEnd := strings.Index(lower[titleStart:], "</title>")
	if titleEnd == -1 {
		return ""
	}

	return strings.TrimSpace(body[titleStart : titleStart+titleEnd])
}
