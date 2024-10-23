package services

import (
	"net"
	"strings"
	"time"
)

func TrySSH(address string, timeout time.Duration) (string, string) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	banner := make([]byte, 64)
	n, err := conn.Read(banner)
	if err != nil || n == 0 {
		return "", ""
	}

	bannerStr := string(banner[:n])
	if strings.HasPrefix(bannerStr, "SSH-") {
		parts := strings.SplitN(bannerStr, " ", 2)
		version := ""
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}
		return "SSH", version
	}

	return "", ""
}
