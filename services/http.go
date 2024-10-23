package services

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"GoKnocker/models"
	"GoKnocker/utils"
)

func ProbeHTTP(host string, port uint16, timeout time.Duration, useTLS bool) *models.HttpInfo {
	info := &models.HttpInfo{}
	protocol := "http"
	if useTLS {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", protocol, host, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout: timeout,
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

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	info.StatusCode = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.ContentType = resp.Header.Get("Content-Type")
	info.Location = resp.Header.Get("Location")
	info.PoweredBy = resp.Header.Get("X-Powered-By")

	if useTLS && resp.TLS != nil {
		info.TLSVersion = utils.GetTLSVersion(resp.TLS.Version)
		info.TLSCipher = utils.GetTLSCipherSuite(resp.TLS.CipherSuite)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			info.TLSCert = fmt.Sprintf("Subject: %s, Issuer: %s, Expires: %s",
				cert.Subject.CommonName,
				cert.Issuer.CommonName,
				cert.NotAfter.Format("2006-01-02"))
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err == nil {
		info.Title = utils.ExtractTitle(string(body))
	}

	return info
}
