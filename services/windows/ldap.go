package windows

import (
	"bytes"
	"net"
	"strings"
	"time"
)

type LDAPService struct {
	timeout time.Duration
}

func NewLDAPService(timeout time.Duration) *LDAPService {
	return &LDAPService{timeout: timeout}
}

func (s *LDAPService) Probe(host string, port uint16) (string, string) {
	serviceName := "LDAP"
	switch port {
	case 636:
		serviceName = "LDAPS"
	case 3268:
		serviceName = "Global Catalog"
	case 3269:
		serviceName = "Global Catalog SSL"
	}

	conn, err := net.DialTimeout("tcp", formatAddress(host, port), s.timeout)
	if err != nil {
		return serviceName, ""
	}
	defer conn.Close()

	// Send LDAP bind request
	bindRequest := buildLDAPBindRequest()
	conn.SetDeadline(time.Now().Add(s.timeout))

	if _, err := conn.Write(bindRequest); err != nil {
		return serviceName, ""
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil || n < 10 {
		return serviceName, ""
	}

	info := "Microsoft Windows Active Directory LDAP"
	if bytes.Contains(response[:n], []byte("DC=")) {
		start := bytes.Index(response[:n], []byte("DC="))
		end := bytes.IndexByte(response[start:], 0x00)
		if end != -1 {
			domain := string(response[start : start+end])
			info += " (Domain: " + strings.ReplaceAll(domain, "DC=", ".") + ")"
		}
	}

	return serviceName, info
}

func buildLDAPBindRequest() []byte {
	// Simple LDAP v3 bind request
	return []byte{
		0x30, 0x0c, // Sequence
		0x02, 0x01, 0x01, // Message ID (1)
		0x60, 0x07, // Bind Request
		0x02, 0x01, 0x03, // Version 3
		0x04, 0x00, // Empty DN
		0x80, 0x00, // Simple authentication
	}
}
