package windows

import (
	"net"
	"time"
)

type DNSService struct {
	timeout time.Duration
}

func NewDNSService(timeout time.Duration) *DNSService {
	return &DNSService{timeout: timeout}
}

func (s *DNSService) Probe(host string, port uint16) (string, string) {
	conn, err := net.DialTimeout("tcp", formatAddress(host, port), s.timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// DNS query for version.bind
	query := buildDNSQuery()

	conn.SetDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write(query); err != nil {
		return "DNS", ""
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		return "DNS", ""
	}

	// Check if it's a valid DNS response
	if n > 12 && response[2]&0x80 != 0 {
		// Try to extract version if available
		if version := extractDNSVersion(response[:n]); version != "" {
			return "DNS", "Simple DNS Plus " + version
		}
		return "DNS", "Simple DNS Plus"
	}

	return "DNS", ""
}

func buildDNSQuery() []byte {
	// DNS query for version.bind TXT record
	return []byte{
		0x00, 0x0c, // Transaction ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,       // Root domain
		0x00, 0x10, // Type TXT
		0x00, 0x03, // Class CH
	}
}

func extractDNSVersion(response []byte) string {
	// Skip header and question
	pos := 12
	for pos < len(response) {
		if response[pos] == 0 {
			break
		}
		pos += int(response[pos]) + 1
	}
	pos += 5 // Skip 0x00 and QTYPE/QCLASS

	if pos+12 >= len(response) {
		return ""
	}

	txtLen := int(response[pos+11])
	if pos+12+txtLen <= len(response) {
		return string(response[pos+12 : pos+12+txtLen])
	}
	return ""
}
