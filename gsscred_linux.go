//go:build linux
// +build linux

// Package main provides gokrb5-based Kerberos authentication on Linux.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// GSSCredTransport provides gokrb5-based authentication on Linux
type GSSCredTransport struct {
	debug      bool
	client     *client.Client
	ccachePath string
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

// NewGSSCredTransport creates a new gokrb5 transport
func NewGSSCredTransport() *GSSCredTransport {
	return &GSSCredTransport{}
}

// IsMacOS11OrLater returns false on Linux
func IsMacOS11OrLater() bool {
	return false
}

// IsWindows returns false on Linux
func IsWindows() bool {
	return false
}

// IsLinux returns true on Linux
func IsLinux() bool {
	return true
}

// SetDebug enables or disables debug output
func (t *GSSCredTransport) SetDebug(debug bool) {
	t.debug = debug
}

// SetCCachePath sets the credential cache path to use
func (t *GSSCredTransport) SetCCachePath(path string) {
	t.ccachePath = path
}

// Connect loads credentials from the ccache and creates a gokrb5 client
func (t *GSSCredTransport) Connect() error {
	// Determine ccache path
	ccachePath := t.ccachePath
	if ccachePath == "" {
		// Check KRB5CCNAME environment variable
		ccachePath = os.Getenv("KRB5CCNAME")
		if ccachePath == "" {
			// Default to /tmp/krb5cc_<uid>
			ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
		}
	}

	// Strip FILE: prefix if present
	ccachePath = strings.TrimPrefix(ccachePath, "FILE:")

	if t.debug {
		fmt.Printf("DEBUG: Loading credentials from ccache: %s\n", ccachePath)
	}

	// Load the credential cache
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return fmt.Errorf("failed to load ccache from %s: %w", ccachePath, err)
	}

	if t.debug {
		fmt.Printf("DEBUG: Loaded ccache for principal: %s@%s\n",
			ccache.DefaultPrincipal.PrincipalName.PrincipalNameString(),
			ccache.DefaultPrincipal.Realm)
	}

	// Load krb5.conf
	krb5ConfPath := os.Getenv("KRB5_CONFIG")
	if krb5ConfPath == "" {
		krb5ConfPath = "/etc/krb5.conf"
	}

	if t.debug {
		fmt.Printf("DEBUG: Loading krb5.conf from: %s\n", krb5ConfPath)
	}

	cfg, err := config.Load(krb5ConfPath)
	if err != nil {
		return fmt.Errorf("failed to load krb5.conf from %s: %w", krb5ConfPath, err)
	}

	// Create client from ccache
	cl, err := client.NewFromCCache(ccache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return fmt.Errorf("failed to create client from ccache: %w", err)
	}
	t.client = cl

	if t.debug {
		fmt.Println("DEBUG: Created gokrb5 client from ccache")
	}

	return nil
}

// Close releases the client resources
func (t *GSSCredTransport) Close() error {
	if t.client != nil {
		t.client.Destroy()
		t.client = nil
	}
	return nil
}

// GetDefaultCache returns the ccache path
func (t *GSSCredTransport) GetDefaultCache() (string, error) {
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath == "" {
		ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
	}
	return ccachePath, nil
}

// GetDefaultPrincipal returns the principal from the ccache
func (t *GSSCredTransport) GetDefaultPrincipal() (string, error) {
	if t.client == nil {
		return "", fmt.Errorf("not connected - call Connect() first")
	}
	creds := t.client.Credentials
	return fmt.Sprintf("%s@%s", creds.UserName(), creds.Realm()), nil
}

// GetCredentials returns credential information (limited implementation)
func (t *GSSCredTransport) GetCredentials() ([]GSSCredInfo, error) {
	return nil, fmt.Errorf("credential enumeration not implemented - use -list flag")
}

// ExportCredential is not supported on Linux
func (t *GSSCredTransport) ExportCredential() ([]byte, error) {
	return nil, fmt.Errorf("credential export not supported on Linux")
}

// GetServiceTicket obtains a service ticket for the specified SPN using gokrb5
// The SPN should be in the format "HTTP/hostname" or "service/hostname"
// Returns the SPNEGO token that can be used for authentication
func (t *GSSCredTransport) GetServiceTicket(spn string) ([]byte, error) {
	if t.client == nil {
		return nil, fmt.Errorf("not connected - call Connect() first")
	}

	if t.debug {
		fmt.Printf("DEBUG: Requesting service ticket for SPN: %s\n", spn)
	}

	// Parse the SPN into service and hostname
	// Format: service/hostname or service@hostname
	var service, hostname string
	if strings.Contains(spn, "/") {
		parts := strings.SplitN(spn, "/", 2)
		service = parts[0]
		hostname = parts[1]
	} else if strings.Contains(spn, "@") {
		parts := strings.SplitN(spn, "@", 2)
		service = parts[0]
		hostname = parts[1]
	} else {
		return nil, fmt.Errorf("invalid SPN format: %s (expected service/hostname or service@hostname)", spn)
	}

	if t.debug {
		fmt.Printf("DEBUG: Parsed SPN - service: %s, hostname: %s\n", service, hostname)
	}

	// Create SPNEGO client and get the initial token
	spnegoClient := spnego.SPNEGOClient(t.client, spn)

	// Get the SPNEGO token
	err := spnegoClient.AcquireCred()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials: %w", err)
	}

	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security context: %w", err)
	}

	// Marshal the SPNEGO token
	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	if t.debug {
		fmt.Printf("DEBUG: Got SPNEGO token of %d bytes\n", len(tokenBytes))
	}

	return tokenBytes, nil
}
