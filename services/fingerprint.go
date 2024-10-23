package services

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ProtocolFingerprint contains methods to identify protocols from responses
type ProtocolFingerprint struct {
	Response []byte
}

// NewFingerprint creates a new protocol fingerprint from response
func NewFingerprint(response []byte) *ProtocolFingerprint {
	return &ProtocolFingerprint{Response: response}
}

// IdentifyProtocol attempts to identify the protocol from the response
func (p *ProtocolFingerprint) IdentifyProtocol() string {
	if len(p.Response) == 0 {
		return ""
	}

	if p.IsHTTP() {
		return "HTTP"
	}
	if p.IsSSH() {
		return "SSH"
	}
	if p.IsSMB() {
		return "SMB"
	}
	if p.IsLDAP() {
		return "LDAP"
	}
	if p.IsDNS() {
		return "DNS"
	}
	if p.IsRPC() {
		return "RPC"
	}
	if p.IsKerberos() {
		return "Kerberos"
	}
	if p.IsFTP() {
		return "FTP"
	}
	if p.IsMSSQL() {
		return "MSSQL"
	}
	if p.IsMySQL() {
		return "MySQL"
	}
	if p.IsRDP() {
		return "RDP"
	}

	return ""
}

// Protocol detection methods
func (p *ProtocolFingerprint) IsHTTP() bool {
	if len(p.Response) < 4 {
		return false
	}

	httpMethods := []string{
		"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"CONNECT ", "OPTIONS ", "TRACE ", "PATCH ",
		"HTTP/"}

	response := string(p.Response)
	for _, method := range httpMethods {
		if strings.HasPrefix(response, method) {
			return true
		}
	}

	// Check for HTTP response
	return strings.HasPrefix(response, "HTTP/")
}

func (p *ProtocolFingerprint) IsSSH() bool {
	return bytes.HasPrefix(p.Response, []byte("SSH-"))
}

func (p *ProtocolFingerprint) IsSMB() bool {
	if len(p.Response) < 5 {
		return false
	}
	return bytes.Equal(p.Response[4:8], []byte{0xff, 0x53, 0x4d, 0x42}) || // SMB1
		bytes.Equal(p.Response[4:8], []byte{0xfe, 0x53, 0x4d, 0x42}) // SMB2
}

func (p *ProtocolFingerprint) IsLDAP() bool {
	if len(p.Response) < 2 {
		return false
	}
	// Check for LDAP message header
	return p.Response[0] == 0x30 && // Sequence
		len(p.Response) > int(p.Response[1])+2
}

func (p *ProtocolFingerprint) IsDNS() bool {
	if len(p.Response) < 12 {
		return false
	}
	// Check DNS header format
	flags := binary.BigEndian.Uint16(p.Response[2:4])
	return (flags & 0x8000) != 0 // Check QR bit
}

func (p *ProtocolFingerprint) IsRPC() bool {
	if len(p.Response) < 10 {
		return false
	}
	// Check RPC header
	return p.Response[0] == 0x05 && // Version 5
		p.Response[2] == 0x0b // Bind packet type
}

func (p *ProtocolFingerprint) IsKerberos() bool {
	if len(p.Response) < 4 {
		return false
	}
	// Check Kerberos message header
	return p.Response[0] == 0x6a && // Application 10
		p.Response[1] == 0x82 // Length field
}

func (p *ProtocolFingerprint) IsFTP() bool {
	response := string(p.Response)
	return strings.HasPrefix(response, "220 ") &&
		(strings.Contains(response, "FTP") ||
			strings.Contains(response, "ftp"))
}

func (p *ProtocolFingerprint) IsMSSQL() bool {
	if len(p.Response) < 8 {
		return false
	}
	// Check for MS-TDS header
	return p.Response[0] == 0x04 && // Type 4 (SQL Server)
		p.Response[1] == 0x01 // Status
}

func (p *ProtocolFingerprint) IsMySQL() bool {
	return len(p.Response) > 4 &&
		bytes.Contains(p.Response, []byte("mysql"))
}

func (p *ProtocolFingerprint) IsRDP() bool {
	return len(p.Response) > 5 &&
		p.Response[0] == 0x03 && // TPKT version 3
		p.Response[1] == 0x00 && // Reserved
		p.Response[4] == 0x02 // X.224 connection confirm
}

// ExtractVersion attempts to extract version information from the response
func (p *ProtocolFingerprint) ExtractVersion() string {
	response := string(p.Response)

	// SSH Version
	if strings.HasPrefix(response, "SSH-") {
		parts := strings.SplitN(response, " ", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}

	// HTTP Server Version
	if strings.Contains(response, "Server: ") {
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Server: ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Server: "))
			}
		}
	}

	// FTP Version
	if strings.HasPrefix(response, "220 ") {
		return strings.TrimSpace(strings.TrimPrefix(response, "220 "))
	}

	return ""
}
