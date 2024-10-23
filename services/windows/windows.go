package windows

import (
	"GoKnocker/services"
	"fmt"
	"time"
)

// Common Windows service ports
var ServicePorts = map[uint16]string{
	53:   "DNS",
	88:   "Kerberos",
	135:  "MSRPC",
	139:  "NetBIOS",
	389:  "LDAP",
	445:  "SMB",
	464:  "Kpasswd",
	593:  "MSRPC-HTTP",
	636:  "LDAPS",
	3268: "Global Catalog",
	3269: "Global Catalog SSL",
	5985: "WinRM",
}

// Helper function used by all services
func formatAddress(host string, port uint16) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// ProbeService is the main entry point for Windows service detection
func ProbeService(host string, port uint16, timeout time.Duration) (string, string) {
	switch port {
	case 53:
		return NewDNSService(timeout).Probe(host, port)

	case 88:
		return "Kerberos", "Microsoft Windows Kerberos"

	case 135, 593:
		return NewRPCService(timeout).Probe(host, port)

	case 139, 445:
		return NewSMBService(timeout).Probe(host, port)

	case 389, 636, 3268, 3269:
		return NewLDAPService(timeout).Probe(host, port)

	case 464:
		return "Kpasswd", "Microsoft Windows Kerberos Password Change"

	case 5985:
		if info := services.ProbeHTTP(host, port, timeout, false); info != nil {
			return "WinRM", "Microsoft HTTPAPI httpd 2.0"
		}
		return "WinRM", ""
	}

	return "", ""
}
