//go:build !darwin
// +build !darwin

// Package main provides stub implementations for GSSCred on non-macOS platforms.
package main

import "fmt"

// GSSCredTransport is a stub for non-macOS platforms
type GSSCredTransport struct {
	debug bool
}

// GSSCredInfo holds credential information (stub for non-macOS)
type GSSCredInfo struct {
	ClientPrincipal string
	ServerPrincipal string
	Lifetime        uint32
	AuthTime        int64
	StartTime       int64
	EndTime         int64
	RenewTill       int64
	KeyType         int32
}

// NewGSSCredTransport creates a stub transport
func NewGSSCredTransport() *GSSCredTransport {
	return &GSSCredTransport{}
}

// IsMacOS11OrLater returns false on non-macOS platforms
func IsMacOS11OrLater() bool {
	return false
}

// SetDebug is a no-op on non-macOS platforms
func (t *GSSCredTransport) SetDebug(debug bool) {
	t.debug = debug
}

// Connect returns an error on non-macOS platforms
func (t *GSSCredTransport) Connect() error {
	return fmt.Errorf("GSSCred is only available on macOS")
}

// Close is a no-op on non-macOS platforms
func (t *GSSCredTransport) Close() error {
	return nil
}

// GetDefaultCache returns an error on non-macOS platforms
func (t *GSSCredTransport) GetDefaultCache() (string, error) {
	return "", fmt.Errorf("GSSCred is only available on macOS")
}

// GetDefaultPrincipal returns an error on non-macOS platforms
func (t *GSSCredTransport) GetDefaultPrincipal() (string, error) {
	return "", fmt.Errorf("GSSCred is only available on macOS")
}

// GetCredentials returns an error on non-macOS platforms
func (t *GSSCredTransport) GetCredentials() ([]GSSCredInfo, error) {
	return nil, fmt.Errorf("GSSCred is only available on macOS")
}

// ExportCredential returns an error on non-macOS platforms
func (t *GSSCredTransport) ExportCredential() ([]byte, error) {
	return nil, fmt.Errorf("GSSCred is only available on macOS")
}

// GetServiceTicket returns an error on non-macOS platforms
func (t *GSSCredTransport) GetServiceTicket(spn string) ([]byte, error) {
	return nil, fmt.Errorf("GSSCred is only available on macOS")
}
