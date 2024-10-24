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

// services/windows/windows.go

func ProbeService(host string, port uint16, timeout time.Duration) (string, string) {
	// Try specific service probes first
	if service, version := trySpecificProbes(host, port, timeout); service != "" {
		return service, version
	}

	// Fall back to generic service mapping
	if serviceName, ok := ServicePorts[port]; ok {
		switch port {
		case 88:
			return "Kerberos", "Microsoft Windows Kerberos"
		case 464:
			return "Kpasswd", "Microsoft Windows Kerberos Password Change"
		case 5985:
			if info := services.ProbeHTTP(host, port, timeout, false); info != nil {
				return "WinRM", "Microsoft HTTPAPI httpd " + info.Server
			}
		}
		return serviceName, fmt.Sprintf("Microsoft Windows %s", serviceName)
	}

	return "", ""
}

func trySpecificProbes(host string, port uint16, timeout time.Duration) (string, string) {
	// Map of port numbers to their specific probe services
	probes := map[uint16]struct {
		service interface {
			Probe(string, uint16) (string, string)
		}
	}{
		53:   {NewDNSService(timeout)},
		135:  {NewRPCService(timeout)},
		139:  {NewSMBService(timeout)},
		389:  {NewLDAPService(timeout)},
		445:  {NewSMBService(timeout)},
		636:  {NewLDAPService(timeout)},
		3268: {NewLDAPService(timeout)},
		3269: {NewLDAPService(timeout)},
	}

	if probeInfo, ok := probes[port]; ok {
		return probeInfo.service.Probe(host, port)
	}
	return "", ""
}
