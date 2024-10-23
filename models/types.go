package models

import (
	"net"
	"time"
)

type HttpInfo struct {
	StatusCode  int
	Server      string
	ContentType string
	Location    string
	Title       string
	PoweredBy   string
	TLSVersion  string
	TLSCipher   string
	TLSCert     string
}

type PortResult struct {
	IP           net.IP
	Port         uint16
	State        string
	Service      string
	Version      string
	Banner       []byte
	HttpInfo     *HttpInfo
	EnhancedInfo map[string]interface{}
	ResponseTime time.Duration
}
