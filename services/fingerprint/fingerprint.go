// services/fingerprint/fingerprint.go

package fingerprint

import (
	"crypto/tls"
	"net"
	"regexp"
	"strings"
	"time"
)

type ServiceFingerprint struct {
	Name       string
	Pattern    *regexp.Regexp
	CustomPort uint16
	ProbeData  []byte
	TLSProbe   bool
}

type ServiceIdentifier struct {
	fingerprints []*ServiceFingerprint
	timeout      time.Duration
}

func NewServiceIdentifier(timeout time.Duration) *ServiceIdentifier {
	return &ServiceIdentifier{
		timeout:      timeout,
		fingerprints: defaultFingerprints(),
	}
}

func (si *ServiceIdentifier) AddFingerprint(fp *ServiceFingerprint) {
	si.fingerprints = append(si.fingerprints, fp)
}

func (si *ServiceIdentifier) IdentifyService(host string, port uint16) (string, string) {
	address := net.JoinHostPort(host, string(port))

	for _, fp := range si.fingerprints {
		// Check if this is a remapped standard service
		if fp.CustomPort > 0 && port == fp.CustomPort {
			if service, version := si.probeService(address, fp); service != "" {
				return service, version
			}
		}

		// Try general fingerprint matching
		if service, version := si.probeService(address, fp); service != "" {
			return service, version
		}
	}

	return "", ""
}

func (si *ServiceIdentifier) probeService(address string, fp *ServiceFingerprint) (string, string) {
	var conn net.Conn
	var err error

	if fp.TLSProbe {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}
		conn, err = tls.Dial("tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, si.timeout)
	}

	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// Send probe data if specified
	if len(fp.ProbeData) > 0 {
		conn.SetWriteDeadline(time.Now().Add(si.timeout))
		if _, err := conn.Write(fp.ProbeData); err != nil {
			return "", ""
		}
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(si.timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return "", ""
	}

	if fp.Pattern.Match(response[:n]) {
		version := extractVersion(response[:n], fp.Name)
		return fp.Name, version
	}

	return "", ""
}

func defaultFingerprints() []*ServiceFingerprint {
	return []*ServiceFingerprint{
		{
			Name:    "SSH",
			Pattern: regexp.MustCompile(`^SSH-[\d.]+`),
		},
		{
			Name:      "HTTP",
			Pattern:   regexp.MustCompile(`^HTTP/[\d.]+`),
			ProbeData: []byte("GET / HTTP/1.0\r\n\r\n"),
		},
		{
			Name:    "FTP",
			Pattern: regexp.MustCompile(`^220[\s-]`),
		},
		{
			Name:    "SMTP",
			Pattern: regexp.MustCompile(`^220[\s-].*SMTP`),
		},
		{
			Name:    "POP3",
			Pattern: regexp.MustCompile(`^\+OK`),
		},
		{
			Name:    "IMAP",
			Pattern: regexp.MustCompile(`^\* OK.*IMAP`),
		},
		{
			Name:     "HTTPS",
			Pattern:  regexp.MustCompile(`.*`),
			TLSProbe: true,
		},
		// Add more fingerprints as needed
	}
}

func extractVersion(response []byte, serviceName string) string {
	responseStr := string(response)

	switch serviceName {
	case "SSH":
		if parts := strings.SplitN(responseStr, " ", 3); len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	case "HTTP", "HTTPS":
		if server := regexp.MustCompile(`Server: (.+)`).FindStringSubmatch(responseStr); len(server) > 1 {
			return server[1]
		}
	case "FTP":
		if version := regexp.MustCompile(`220[- ](.+)`).FindStringSubmatch(responseStr); len(version) > 1 {
			return strings.TrimSpace(version[1])
		}
	}

	return ""
}
