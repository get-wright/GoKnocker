package services

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strings"
)

// ProtocolFingerprint contains methods to identify protocols from responses
type ProtocolFingerprint struct {
	Response []byte
}

// Common protocol patterns
var (
	kerberosPattern = []byte{0x6a, 0x82} // ASN.1 Kerberos tag
	vmrdpPattern    = []byte{0x03, 0x00} // RDP protocol identifier
	dotnetPattern   = []byte{0x0e, 0x00} // .NET Binary Format

	// Version extraction patterns
	versionRegex  = regexp.MustCompile(`(?i)(?:version|ver)[:\s]+([0-9][0-9a-zA-Z._\-]+)`)
	mssqlRegex    = regexp.MustCompile(`(?i)Microsoft SQL Server\s+([0-9][0-9a-zA-Z._\-]+)`)
	kerberosRegex = regexp.MustCompile(`(?i)kerberos\s+([0-9][0-9a-zA-Z._\-]+)`)
)

// NewFingerprint creates a new protocol fingerprint from response
func NewFingerprint(response []byte) *ProtocolFingerprint {
	return &ProtocolFingerprint{Response: response}
}

// IdentifyProtocol attempts to identify the protocol from the response
func (p *ProtocolFingerprint) IdentifyProtocol() string {
	if len(p.Response) == 0 {
		return ""
	}

	// Try to identify protocols in order of complexity and uniqueness
	switch {
	case p.IsHTTP():
		return "HTTP"
	case p.IsSSH():
		return "SSH"
	case p.IsSMB():
		return "SMB"
	case p.IsLDAP():
		return "LDAP"
	case p.IsDNS():
		return "DNS"
	case p.IsRPC():
		return "RPC"
	case p.IsKerberos():
		return "KERBEROS"
	case p.IsFTP():
		return "FTP"
	case p.IsMSSQL():
		return "MSSQL"
	case p.IsMySQL():
		return "MySQL"
	case p.IsRDP():
		return "RDP"
	case p.IsVMRDP():
		return "VMRDP"
	case p.IsDotNet():
		return "DOTNET"
	case p.IsPOP3():
		return "POP3"
	case p.IsIMAP():
		return "IMAP"
	case p.IsSMTP():
		return "SMTP"
	case p.IsNTLM():
		return "NTLM"
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
	return p.Response[0] == 0x30 && // Sequence
		len(p.Response) > int(p.Response[1])+2
}

func (p *ProtocolFingerprint) IsDNS() bool {
	if len(p.Response) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(p.Response[2:4])
	return (flags & 0x8000) != 0 // Check QR bit
}

func (p *ProtocolFingerprint) IsRPC() bool {
	if len(p.Response) < 10 {
		return false
	}
	return p.Response[0] == 0x05 && // Version 5
		p.Response[2] == 0x0b // Bind packet type
}

func (p *ProtocolFingerprint) IsKerberos() bool {
	if len(p.Response) < 4 {
		return false
	}
	return bytes.HasPrefix(p.Response, kerberosPattern)
}

func (p *ProtocolFingerprint) IsFTP() bool {
	response := string(p.Response)
	return strings.HasPrefix(response, "220 ") &&
		(strings.Contains(strings.ToLower(response), "ftp") ||
			strings.Contains(response, "FileZilla"))
}

func (p *ProtocolFingerprint) IsMSSQL() bool {
	if len(p.Response) < 8 {
		return false
	}
	return p.Response[0] == 0x04 && // Type 4 (SQL Server)
		p.Response[1] == 0x01 // Status
}

func (p *ProtocolFingerprint) IsMySQL() bool {
	return len(p.Response) > 4 &&
		bytes.Contains(bytes.ToLower(p.Response), []byte("mysql"))
}

func (p *ProtocolFingerprint) IsRDP() bool {
	if len(p.Response) < 5 {
		return false
	}
	return p.Response[0] == 0x03 && // TPKT version 3
		p.Response[1] == 0x00 && // Reserved
		p.Response[4] == 0x02 // X.224 connection confirm
}

func (p *ProtocolFingerprint) IsVMRDP() bool {
	if len(p.Response) < 4 {
		return false
	}
	return bytes.HasPrefix(p.Response, vmrdpPattern)
}

func (p *ProtocolFingerprint) IsDotNet() bool {
	if len(p.Response) < 4 {
		return false
	}
	return bytes.HasPrefix(p.Response, dotnetPattern)
}

func (p *ProtocolFingerprint) IsPOP3() bool {
	response := string(p.Response)
	return strings.HasPrefix(response, "+OK") &&
		strings.Contains(strings.ToLower(response), "pop3")
}

func (p *ProtocolFingerprint) IsIMAP() bool {
	response := string(p.Response)
	return strings.HasPrefix(response, "* OK") &&
		strings.Contains(strings.ToLower(response), "imap")
}

func (p *ProtocolFingerprint) IsSMTP() bool {
	response := string(p.Response)
	return strings.HasPrefix(response, "220") &&
		strings.Contains(strings.ToLower(response), "smtp")
}

func (p *ProtocolFingerprint) IsNTLM() bool {
	return bytes.Contains(p.Response, []byte("NTLMSSP"))
}

// ExtractVersion attempts to extract version information from the response
func (p *ProtocolFingerprint) ExtractVersion() string {
	response := string(p.Response)

	// Try protocol-specific version extraction first
	switch {
	case p.IsMSSQL():
		if matches := mssqlRegex.FindStringSubmatch(response); len(matches) > 1 {
			return "Microsoft SQL Server " + matches[1]
		}
	case p.IsKerberos():
		if matches := kerberosRegex.FindStringSubmatch(response); len(matches) > 1 {
			return "Microsoft Windows Kerberos " + matches[1]
		}
	case p.IsSSH():
		parts := strings.SplitN(response, " ", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}

	// Try general version extraction
	if matches := versionRegex.FindStringSubmatch(response); len(matches) > 1 {
		return matches[1]
	}

	// Look for version-like patterns in hex
	hexStr := hex.EncodeToString(p.Response)
	if matches := regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+)`).FindString(hexStr); matches != "" {
		return matches
	}

	return ""
}
