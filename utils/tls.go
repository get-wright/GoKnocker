package utils

import (
	"crypto/tls"
	"fmt"
)

func GetTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func GetTLSCipherSuite(cipher uint16) string {
	switch cipher {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "RSA-AES128-CBC-SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "RSA-AES256-CBC-SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "ECDHE-RSA-AES128-CBC-SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "ECDHE-RSA-AES256-CBC-SHA"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", cipher)
	}
}
