//go:build windows
// +build windows

// Package main provides SSPI-based Kerberos authentication on Windows.
package main

import (
	"fmt"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
)

// GSSCredTransport provides SSPI-based authentication on Windows
type GSSCredTransport struct {
	debug bool
	cred  *sspi.Credentials
}

// GSSCredInfo holds credential information
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

// NewGSSCredTransport creates a new SSPI transport
func NewGSSCredTransport() *GSSCredTransport {
	return &GSSCredTransport{}
}

// IsMacOS11OrLater returns false on Windows (not applicable)
func IsMacOS11OrLater() bool {
	return false
}

// IsWindows returns true on Windows
func IsWindows() bool {
	return true
}

// IsLinux returns false on Windows
func IsLinux() bool {
	return false
}

// SetDebug enables or disables debug output
func (t *GSSCredTransport) SetDebug(debug bool) {
	t.debug = debug
}

// SetCCachePath is a no-op on Windows (SSPI manages credentials)
func (t *GSSCredTransport) SetCCachePath(path string) {
	// Windows SSPI uses LSA credential cache, path is ignored
}

// Connect acquires current user credentials via SSPI
func (t *GSSCredTransport) Connect() error {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return fmt.Errorf("failed to acquire credentials: %w", err)
	}
	t.cred = cred
	if t.debug {
		fmt.Println("DEBUG: Acquired current user credentials via SSPI")
	}
	return nil
}

// Close releases the credentials
func (t *GSSCredTransport) Close() error {
	if t.cred != nil {
		t.cred.Release()
		t.cred = nil
	}
	return nil
}

// GetDefaultCache returns a placeholder on Windows (SSPI doesn't expose cache names)
func (t *GSSCredTransport) GetDefaultCache() (string, error) {
	return "SSPI", nil
}

// GetDefaultPrincipal returns the current user principal
func (t *GSSCredTransport) GetDefaultPrincipal() (string, error) {
	// SSPI doesn't directly expose the principal name from credentials
	// We'd need to create a context and query it
	return "", fmt.Errorf("GetDefaultPrincipal not implemented on Windows")
}

// GetCredentials returns credential information (limited on Windows)
func (t *GSSCredTransport) GetCredentials() ([]GSSCredInfo, error) {
	// SSPI doesn't provide a way to enumerate credentials like GSS API
	return nil, fmt.Errorf("credential enumeration not available via SSPI")
}

// ExportCredential is not supported on Windows via SSPI
func (t *GSSCredTransport) ExportCredential() ([]byte, error) {
	return nil, fmt.Errorf("credential export not supported on Windows")
}

// GetServiceTicket obtains a service ticket for the specified SPN using SSPI
// The SPN should be in the format "HTTP/hostname" or "HTTP@hostname"
// Returns the SPNEGO/Kerberos token that can be used for authentication
func (t *GSSCredTransport) GetServiceTicket(spn string) ([]byte, error) {
	if t.cred == nil {
		return nil, fmt.Errorf("not connected - call Connect() first")
	}

	if t.debug {
		fmt.Printf("DEBUG: Requesting service ticket for SPN: %s\n", spn)
	}

	// Create a client context for the target SPN
	// This will request a service ticket from the KDC
	ctx, token, err := negotiate.NewClientContext(t.cred, spn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security context: %w", err)
	}
	defer ctx.Release()

	if t.debug {
		fmt.Printf("DEBUG: SSPI returned token of %d bytes\n", len(token))
	}

	// The first call to NewClientContext returns the initial token
	// For Kerberos, this is typically the complete AP-REQ wrapped in SPNEGO
	if len(token) == 0 {
		return nil, fmt.Errorf("SSPI returned empty token")
	}

	return token, nil
}
