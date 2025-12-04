// Package main provides a cross-platform credential cache abstraction.
// On macOS, it uses KCM (Kerberos Credential Manager) via Mach RPC.
// On Linux, it uses file-based credential caches.
package main

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

// krb5cli configuration struct
type Config struct {
	Realm      string
	SPN        string
	Keytab     string
	Krb5Config string
	UseCC      bool
	ListCreds  bool
	CacheName  string
	Debug      bool
}

// Global debug flag for credential cache operations
var debugMode bool

// SetDebugMode enables or disables debug output
func SetDebugMode(debug bool) {
	debugMode = debug
}

// CCache is the interface for credential cache implementations.
// It abstracts the platform-specific credential storage mechanisms.
type CCache interface {
	// Close closes the credential cache connection/handle
	Close() error

	// GetDefaultCacheName returns the name of the default credential cache
	GetDefaultCacheName() (string, error)

	// SetDefaultCache sets the default credential cache by name
	SetDefaultCache(name string) error

	// ListCaches returns a list of available cache names
	ListCaches() ([]string, error)

	// OpenCache opens a credential cache by name (empty string for default)
	OpenCache(name string) (CCacheHandle, error)

	// CreateCache creates a new credential cache with a unique name
	CreateCache() (CCacheHandle, error)
}

// CCacheHandle represents an open credential cache
type CCacheHandle interface {
	// Name returns the name/identifier of this cache
	Name() string

	// Close closes this cache handle
	Close() error

	// Initialize initializes the cache with a principal
	Initialize(principal types.PrincipalName, realm string) error

	// Destroy destroys the credential cache
	Destroy() error

	// GetPrincipal returns the default principal of the cache
	GetPrincipal() (types.PrincipalName, string, error)

	// Store stores a credential in the cache
	Store(cred *Credential) error

	// Retrieve retrieves a credential matching the server principal
	Retrieve(server types.PrincipalName, serverRealm string) (*Credential, error)

	// GetCredentials returns all credentials in the cache
	GetCredentials() ([]*Credential, error)

	// RemoveCredential removes a credential from the cache
	RemoveCredential(server types.PrincipalName, serverRealm string) error
}

// Credential represents a Kerberos credential (ticket + session key)
type Credential struct {
	Client       types.PrincipalName
	ClientRealm  string
	Server       types.PrincipalName
	ServerRealm  string
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// String returns a human-readable representation of the credential
func (cred *Credential) String() string {
	return fmt.Sprintf("Client: %s@%s, Server: %s@%s, EndTime: %s",
		cred.Client.PrincipalNameString(),
		cred.ClientRealm,
		cred.Server.PrincipalNameString(),
		cred.ServerRealm,
		cred.EndTime.Format(time.RFC3339))
}

// IsExpired returns true if the credential has expired
func (cred *Credential) IsExpired() bool {
	return time.Now().After(cred.EndTime)
}

// IsValid returns true if the credential is currently valid (started and not expired)
func (cred *Credential) IsValid() bool {
	now := time.Now()
	return now.After(cred.StartTime) && now.Before(cred.EndTime)
}

// TimeRemaining returns the duration until the credential expires
func (cred *Credential) TimeRemaining() time.Duration {
	return time.Until(cred.EndTime)
}

// NewCCache creates a new credential cache client for the current platform.
// On macOS, this connects to the KCM daemon via Mach RPC.
// On Linux, this uses file-based credential caches.
func NewCCache() (CCache, error) {
	return newPlatformCCache()
}

// Common error types
var (
	ErrCacheNotFound = fmt.Errorf("credential cache not found")
	ErrCredNotFound  = fmt.Errorf("credential not found")
	ErrNoServer      = fmt.Errorf("credential cache server not available")
)
