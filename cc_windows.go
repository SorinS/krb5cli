//go:build windows
// +build windows

// Package main provides SSPI-based credential cache for Windows.
// On Windows, credentials are managed by SSPI/LSA rather than file-based ccache.
package main

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/types"
)

// windowsCCache implements CCache for Windows using SSPI
type windowsCCache struct {
}

// windowsCCacheHandle implements CCacheHandle for Windows
type windowsCCacheHandle struct {
	name string
}

// newPlatformCCache creates a new SSPI-based credential cache for Windows
func newPlatformCCache() (CCache, error) {
	return &windowsCCache{}, nil
}

// Close closes the credential cache connection
func (cc *windowsCCache) Close() error {
	return nil
}

// GetDefaultCacheName returns a placeholder name for Windows SSPI
func (cc *windowsCCache) GetDefaultCacheName() (string, error) {
	return "MSLSA:", nil
}

// SetDefaultCache is not supported on Windows
func (cc *windowsCCache) SetDefaultCache(name string) error {
	return fmt.Errorf("SetDefaultCache not supported on Windows - use SSPI")
}

// ListCaches returns a single SSPI cache entry
func (cc *windowsCCache) ListCaches() ([]string, error) {
	return []string{"MSLSA:"}, nil
}

// OpenCache opens the SSPI credential cache
func (cc *windowsCCache) OpenCache(name string) (CCacheHandle, error) {
	return &windowsCCacheHandle{name: "MSLSA:"}, nil
}

// CreateCache is not supported on Windows
func (cc *windowsCCache) CreateCache() (CCacheHandle, error) {
	return nil, fmt.Errorf("CreateCache not supported on Windows - credentials managed by LSA")
}

// windowsCCacheHandle methods

// Name returns the cache name
func (h *windowsCCacheHandle) Name() string {
	return h.name
}

// Close closes the cache handle
func (h *windowsCCacheHandle) Close() error {
	return nil
}

// Initialize is not supported on Windows
func (h *windowsCCacheHandle) Initialize(principal types.PrincipalName, realm string) error {
	return fmt.Errorf("Initialize not supported on Windows - credentials managed by LSA")
}

// Destroy is not supported on Windows
func (h *windowsCCacheHandle) Destroy() error {
	return fmt.Errorf("Destroy not supported on Windows - credentials managed by LSA")
}

// GetPrincipal returns the current user principal
func (h *windowsCCacheHandle) GetPrincipal() (types.PrincipalName, string, error) {
	// On Windows, we'd need to query the current user's Kerberos principal
	// This would require additional SSPI calls
	return types.PrincipalName{}, "", fmt.Errorf("GetPrincipal not implemented on Windows - use SSPI GetServiceTicket")
}

// Store is not supported on Windows
func (h *windowsCCacheHandle) Store(cred *Credential) error {
	return fmt.Errorf("Store not supported on Windows - credentials managed by LSA")
}

// Retrieve is not supported on Windows
func (h *windowsCCacheHandle) Retrieve(server types.PrincipalName, serverRealm string) (*Credential, error) {
	return nil, fmt.Errorf("Retrieve not supported on Windows - use SSPI GetServiceTicket")
}

// GetCredentials returns cached credentials
func (h *windowsCCacheHandle) GetCredentials() ([]*Credential, error) {
	// SSPI doesn't provide direct enumeration of cached tickets
	// The klist command on Windows uses different APIs (LSA)
	return nil, fmt.Errorf("GetCredentials not implemented on Windows - use 'klist' command")
}

// RemoveCredential is not supported on Windows
func (h *windowsCCacheHandle) RemoveCredential(server types.PrincipalName, serverRealm string) error {
	return fmt.Errorf("RemoveCredential not supported on Windows - use 'klist purge'")
}
