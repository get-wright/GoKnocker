package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"GoKnocker/models"
	"GoKnocker/utils"
)

type EnhancedHttpInfo struct {
	models.HttpInfo
	SecurityHeaders  map[string]string
	TLSFingerprint   string
	CertificateChain []CertInfo
	HTTPMethods      []string
	WebServer        ServerInfo
}

type CertInfo struct {
	Subject         string
	Issuer          string
	ValidFrom       time.Time
	ValidTo         time.Time
	SerialNumber    string
	SignatureAlg    string
	SubjectAltNames []string
}

type ServerInfo struct {
	Name       string
	Version    string
	Technology string
}

var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-XSS-Protection",
	"Permissions-Policy",
	"Referrer-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Resource-Policy",
}

var httpMethods = []string{
	"GET", "HEAD", "POST", "PUT", "DELETE",
	"OPTIONS", "TRACE", "CONNECT", "PATCH",
}

// Common cipher suites
var defaultCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

func ProbeHTTPS(host string, port uint16, timeout time.Duration) (*models.HttpInfo, map[string]interface{}) {
	baseInfo := &models.HttpInfo{}
	enhancedInfo := make(map[string]interface{})

	url := fmt.Sprintf("https://%s:%d", host, port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       defaultCipherSuites,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
		Dial: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: timeout,
		}).Dial,
		TLSHandshakeTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Store supported HTTP methods
	enhancedInfo["methods"] = probeHTTPMethods(client, url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GoKnocker/1.0)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Basic HTTP info
	baseInfo.StatusCode = resp.StatusCode
	baseInfo.Server = resp.Header.Get("Server")
	baseInfo.ContentType = resp.Header.Get("Content-Type")
	baseInfo.Location = resp.Header.Get("Location")
	baseInfo.PoweredBy = resp.Header.Get("X-Powered-By")

	// Security headers
	secHeaders := make(map[string]string)
	for _, header := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			secHeaders[header] = value
		}
	}
	enhancedInfo["security_headers"] = secHeaders

	// TLS information
	if resp.TLS != nil {
		baseInfo.TLSVersion = utils.GetTLSVersion(resp.TLS.Version)
		baseInfo.TLSCipher = utils.GetTLSCipherSuite(resp.TLS.CipherSuite)

		// Generate TLS fingerprint based on version and cipher suite
		enhancedInfo["tls_fingerprint"] = fmt.Sprintf("%s-%s",
			baseInfo.TLSVersion,
			baseInfo.TLSCipher)

		// Certificate chain
		var certChain []CertInfo
		for _, cert := range resp.TLS.PeerCertificates {
			certInfo := CertInfo{
				Subject:      cert.Subject.CommonName,
				Issuer:       cert.Issuer.CommonName,
				ValidFrom:    cert.NotBefore,
				ValidTo:      cert.NotAfter,
				SerialNumber: cert.SerialNumber.String(),
				SignatureAlg: cert.SignatureAlgorithm.String(),
			}

			for _, san := range cert.DNSNames {
				certInfo.SubjectAltNames = append(certInfo.SubjectAltNames, san)
			}
			for _, san := range cert.IPAddresses {
				certInfo.SubjectAltNames = append(certInfo.SubjectAltNames, san.String())
			}

			certChain = append(certChain, certInfo)
		}
		enhancedInfo["certificate_chain"] = certChain

		// Store protocol version for additional analysis
		enhancedInfo["protocol_version"] = resp.TLS.Version
		enhancedInfo["negotiated_protocol"] = resp.TLS.NegotiatedProtocol
		enhancedInfo["server_name"] = resp.TLS.ServerName
	}

	// Web server info
	serverInfo := parseServerHeader(resp.Header)
	enhancedInfo["server_info"] = serverInfo

	// Page title
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err == nil {
		baseInfo.Title = utils.ExtractTitle(string(body))
	}

	return baseInfo, enhancedInfo
}

func parseServerHeader(header http.Header) ServerInfo {
	server := header.Get("Server")
	if server == "" {
		return ServerInfo{}
	}

	info := ServerInfo{
		Name: server,
	}

	parts := strings.Split(server, "/")
	if len(parts) > 1 {
		info.Name = parts[0]
		info.Version = parts[1]
	}

	if poweredBy := header.Get("X-Powered-By"); poweredBy != "" {
		info.Technology = poweredBy
	}

	return info
}

func probeHTTPMethods(client *http.Client, url string) []string {
	var supported []string

	for _, method := range httpMethods {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound &&
			resp.StatusCode != http.StatusMethodNotAllowed {
			supported = append(supported, method)
		}
	}

	return supported
}
