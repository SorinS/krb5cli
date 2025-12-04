//go:build linux
// +build linux

// Package main provides a file-based credential cache implementation for Linux.
// This reads credential caches in the MIT Kerberos ccache file format.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

// File ccache constants
const (
	ccacheFileMagic   = 0x05       // First byte of ccache file
	ccacheVersion4    = 4          // Current ccache version
	ccacheDefaultDir  = "/tmp"     // Default ccache directory
	ccacheFilePrefix  = "krb5cc_"  // Default ccache file prefix
)

var (
	errInvalidCCache = errors.New("invalid credential cache file")
	errCCacheVersion = errors.New("unsupported credential cache version")
)

// linuxCCache implements CCache for Linux using file-based ccache
type linuxCCache struct {
	defaultPath string
}

// linuxCCacheHandle implements CCacheHandle for Linux file-based ccache
type linuxCCacheHandle struct {
	path        string
	version     uint8
	principal   types.PrincipalName
	realm       string
	credentials []*Credential
	loaded      bool
}

// newPlatformCCache creates a new file-based credential cache for Linux
func newPlatformCCache() (CCache, error) {
	cc := &linuxCCache{
		defaultPath: getDefaultCCachePath(),
	}
	return cc, nil
}

// getDefaultCCachePath returns the default ccache file path
func getDefaultCCachePath() string {
	// Check KRB5CCNAME environment variable first
	if path := os.Getenv("KRB5CCNAME"); path != "" {
		// Handle FILE: prefix
		if strings.HasPrefix(path, "FILE:") {
			return strings.TrimPrefix(path, "FILE:")
		}
		return path
	}

	// Default to /tmp/krb5cc_<uid>
	return filepath.Join(ccacheDefaultDir, fmt.Sprintf("%s%d", ccacheFilePrefix, os.Getuid()))
}

// Close closes the credential cache (no-op for file-based)
func (c *linuxCCache) Close() error {
	return nil
}

// GetDefaultCacheName returns the name/path of the default credential cache
func (c *linuxCCache) GetDefaultCacheName() (string, error) {
	return c.defaultPath, nil
}

// SetDefaultCache sets the default credential cache (updates environment)
func (c *linuxCCache) SetDefaultCache(name string) error {
	c.defaultPath = name
	return os.Setenv("KRB5CCNAME", "FILE:"+name)
}

// ListCaches returns a list of available cache paths
func (c *linuxCCache) ListCaches() ([]string, error) {
	// Look for ccache files in /tmp
	pattern := filepath.Join(ccacheDefaultDir, ccacheFilePrefix+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Also include the default cache if it exists and isn't in the list
	if c.defaultPath != "" {
		if _, err := os.Stat(c.defaultPath); err == nil {
			found := false
			for _, m := range matches {
				if m == c.defaultPath {
					found = true
					break
				}
			}
			if !found {
				matches = append(matches, c.defaultPath)
			}
		}
	}

	return matches, nil
}

// OpenCache opens a credential cache by path (empty string for default)
func (c *linuxCCache) OpenCache(name string) (CCacheHandle, error) {
	if name == "" {
		name = c.defaultPath
	}

	handle := &linuxCCacheHandle{
		path: name,
	}

	// Try to load the cache
	if err := handle.load(); err != nil {
		// Return handle even if file doesn't exist - it can be initialized later
		if !os.IsNotExist(err) {
			return nil, err
		}
		handle.loaded = false
	}

	return handle, nil
}

// CreateCache creates a new credential cache with a unique name
func (c *linuxCCache) CreateCache() (CCacheHandle, error) {
	// Generate a unique filename
	f, err := os.CreateTemp(ccacheDefaultDir, ccacheFilePrefix)
	if err != nil {
		return nil, err
	}
	path := f.Name()
	f.Close()

	return &linuxCCacheHandle{
		path:   path,
		loaded: false,
	}, nil
}

// Name returns the path of the cache
func (h *linuxCCacheHandle) Name() string {
	return h.path
}

// Close closes this cache handle (no-op for file-based)
func (h *linuxCCacheHandle) Close() error {
	return nil
}

// Initialize initializes the cache with a principal
func (h *linuxCCacheHandle) Initialize(principal types.PrincipalName, realm string) error {
	h.principal = principal
	h.realm = realm
	h.credentials = nil
	h.loaded = true
	return h.save()
}

// Destroy destroys the credential cache
func (h *linuxCCacheHandle) Destroy() error {
	return os.Remove(h.path)
}

// GetPrincipal returns the default principal of the cache
func (h *linuxCCacheHandle) GetPrincipal() (types.PrincipalName, string, error) {
	if !h.loaded {
		if err := h.load(); err != nil {
			return types.PrincipalName{}, "", err
		}
	}

	if len(h.principal.NameString) == 0 {
		return types.PrincipalName{}, "", ErrCacheNotFound
	}

	return h.principal, h.realm, nil
}

// Store stores a credential in the cache
func (h *linuxCCacheHandle) Store(cred *Credential) error {
	if !h.loaded {
		if err := h.load(); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Check if credential already exists and replace it
	found := false
	for i, c := range h.credentials {
		if c.Server.Equal(cred.Server) && c.ServerRealm == cred.ServerRealm {
			h.credentials[i] = cred
			found = true
			break
		}
	}

	if !found {
		h.credentials = append(h.credentials, cred)
	}

	return h.save()
}

// Retrieve retrieves a credential matching the server principal
func (h *linuxCCacheHandle) Retrieve(server types.PrincipalName, serverRealm string) (*Credential, error) {
	if !h.loaded {
		if err := h.load(); err != nil {
			return nil, err
		}
	}

	for _, cred := range h.credentials {
		if cred.Server.Equal(server) && cred.ServerRealm == serverRealm {
			return cred, nil
		}
	}

	return nil, ErrCredNotFound
}

// GetCredentials returns all credentials in the cache
func (h *linuxCCacheHandle) GetCredentials() ([]*Credential, error) {
	if !h.loaded {
		if err := h.load(); err != nil {
			return nil, err
		}
	}

	// Filter out configuration entries
	creds := make([]*Credential, 0, len(h.credentials))
	for _, cred := range h.credentials {
		// Skip X-CACHECONF entries
		if strings.HasPrefix(cred.ServerRealm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}

	return creds, nil
}

// RemoveCredential removes a credential from the cache
func (h *linuxCCacheHandle) RemoveCredential(server types.PrincipalName, serverRealm string) error {
	if !h.loaded {
		if err := h.load(); err != nil {
			return err
		}
	}

	for i, cred := range h.credentials {
		if cred.Server.Equal(server) && cred.ServerRealm == serverRealm {
			h.credentials = append(h.credentials[:i], h.credentials[i+1:]...)
			return h.save()
		}
	}

	return ErrCredNotFound
}

// load reads the credential cache from disk
func (h *linuxCCacheHandle) load() error {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return err
	}

	return h.unmarshal(data)
}

// save writes the credential cache to disk
func (h *linuxCCacheHandle) save() error {
	data, err := h.marshal()
	if err != nil {
		return err
	}

	return os.WriteFile(h.path, data, 0600)
}

// unmarshal parses credential cache data
func (h *linuxCCacheHandle) unmarshal(data []byte) error {
	if len(data) < 2 {
		return errInvalidCCache
	}

	p := 0

	// First byte must be 5
	if data[p] != ccacheFileMagic {
		return errInvalidCCache
	}
	p++

	// Version (1-4)
	h.version = data[p]
	if h.version < 1 || h.version > 4 {
		return errCCacheVersion
	}
	p++

	// Determine byte order
	var endian binary.ByteOrder = binary.BigEndian
	if (h.version == 1 || h.version == 2) && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	// Skip header for version 4
	if h.version == 4 {
		if p+2 > len(data) {
			return errInvalidCCache
		}
		headerLen := int(endian.Uint16(data[p:]))
		p += 2 + headerLen
	}

	// Read default principal
	h.principal, h.realm, p = parsePrincipal(data, p, h.version, endian)

	// Read credentials
	h.credentials = nil
	for p < len(data) {
		cred, newPos, err := parseCredential(data, p, h.version, endian)
		if err != nil {
			return err
		}
		p = newPos
		h.credentials = append(h.credentials, cred)
	}

	h.loaded = true
	return nil
}

// marshal serializes credential cache data
func (h *linuxCCacheHandle) marshal() ([]byte, error) {
	var buf []byte

	// Write magic and version
	buf = append(buf, ccacheFileMagic, ccacheVersion4)

	// Write empty header for version 4
	buf = append(buf, 0, 0) // header length = 0

	// Write default principal
	buf = append(buf, marshalPrincipal(h.principal, h.realm, ccacheVersion4)...)

	// Write credentials
	for _, cred := range h.credentials {
		buf = append(buf, marshalCredential(cred, ccacheVersion4)...)
	}

	return buf, nil
}

// parsePrincipal parses a principal from ccache data
func parsePrincipal(data []byte, p int, version uint8, endian binary.ByteOrder) (types.PrincipalName, string, int) {
	var princ types.PrincipalName

	// Name type (omitted in version 1)
	if version != 1 {
		princ.NameType = int32(endian.Uint32(data[p:]))
		p += 4
	}

	// Number of components
	numComponents := int(endian.Uint32(data[p:]))
	p += 4

	// In version 1, numComponents includes the realm
	if version == 1 {
		numComponents--
	}

	// Realm
	realmLen := int(endian.Uint32(data[p:]))
	p += 4
	realm := string(data[p : p+realmLen])
	p += realmLen

	// Components
	princ.NameString = make([]string, numComponents)
	for i := 0; i < numComponents; i++ {
		compLen := int(endian.Uint32(data[p:]))
		p += 4
		princ.NameString[i] = string(data[p : p+compLen])
		p += compLen
	}

	return princ, realm, p
}

// parseCredential parses a credential from ccache data
func parseCredential(data []byte, p int, version uint8, endian binary.ByteOrder) (*Credential, int, error) {
	cred := &Credential{}

	// Client principal
	cred.Client, cred.ClientRealm, p = parsePrincipal(data, p, version, endian)

	// Server principal
	cred.Server, cred.ServerRealm, p = parsePrincipal(data, p, version, endian)

	// Key type
	keyType := int32(endian.Uint16(data[p:]))
	p += 2

	// Version 3 repeats key type
	if version == 3 {
		keyType = int32(endian.Uint16(data[p:]))
		p += 2
	}

	// Key data
	keyLen := int(endian.Uint32(data[p:]))
	p += 4
	keyValue := make([]byte, keyLen)
	copy(keyValue, data[p:p+keyLen])
	p += keyLen

	cred.Key = types.EncryptionKey{
		KeyType:  keyType,
		KeyValue: keyValue,
	}

	// Times
	cred.AuthTime = time.Unix(int64(endian.Uint32(data[p:])), 0)
	p += 4
	cred.StartTime = time.Unix(int64(endian.Uint32(data[p:])), 0)
	p += 4
	cred.EndTime = time.Unix(int64(endian.Uint32(data[p:])), 0)
	p += 4
	cred.RenewTill = time.Unix(int64(endian.Uint32(data[p:])), 0)
	p += 4

	// is_skey
	cred.IsSKey = data[p] != 0
	p++

	// Ticket flags
	cred.TicketFlags = asn1.BitString{
		Bytes:     make([]byte, 4),
		BitLength: 32,
	}
	copy(cred.TicketFlags.Bytes, data[p:p+4])
	p += 4

	// Addresses
	numAddrs := int(endian.Uint32(data[p:]))
	p += 4
	cred.Addresses = make([]types.HostAddress, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrType := int32(endian.Uint16(data[p:]))
		p += 2
		addrLen := int(endian.Uint32(data[p:]))
		p += 4
		addrData := make([]byte, addrLen)
		copy(addrData, data[p:p+addrLen])
		p += addrLen
		cred.Addresses[i] = types.HostAddress{
			AddrType: addrType,
			Address:  addrData,
		}
	}

	// Auth data
	numAuthData := int(endian.Uint32(data[p:]))
	p += 4
	cred.AuthData = make([]types.AuthorizationDataEntry, numAuthData)
	for i := 0; i < numAuthData; i++ {
		adType := int32(endian.Uint16(data[p:]))
		p += 2
		adLen := int(endian.Uint32(data[p:]))
		p += 4
		adData := make([]byte, adLen)
		copy(adData, data[p:p+adLen])
		p += adLen
		cred.AuthData[i] = types.AuthorizationDataEntry{
			ADType: adType,
			ADData: adData,
		}
	}

	// Ticket
	ticketLen := int(endian.Uint32(data[p:]))
	p += 4
	cred.Ticket = make([]byte, ticketLen)
	copy(cred.Ticket, data[p:p+ticketLen])
	p += ticketLen

	// Second ticket
	ticket2Len := int(endian.Uint32(data[p:]))
	p += 4
	cred.SecondTicket = make([]byte, ticket2Len)
	copy(cred.SecondTicket, data[p:p+ticket2Len])
	p += ticket2Len

	return cred, p, nil
}

// marshalPrincipal serializes a principal
func marshalPrincipal(princ types.PrincipalName, realm string, version uint8) []byte {
	var buf []byte

	// Name type
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(princ.NameType))
	buf = append(buf, tmp...)

	// Number of components
	binary.BigEndian.PutUint32(tmp, uint32(len(princ.NameString)))
	buf = append(buf, tmp...)

	// Realm
	binary.BigEndian.PutUint32(tmp, uint32(len(realm)))
	buf = append(buf, tmp...)
	buf = append(buf, []byte(realm)...)

	// Components
	for _, comp := range princ.NameString {
		binary.BigEndian.PutUint32(tmp, uint32(len(comp)))
		buf = append(buf, tmp...)
		buf = append(buf, []byte(comp)...)
	}

	return buf
}

// marshalCredential serializes a credential
func marshalCredential(cred *Credential, version uint8) []byte {
	var buf []byte

	// Client principal
	buf = append(buf, marshalPrincipal(cred.Client, cred.ClientRealm, version)...)

	// Server principal
	buf = append(buf, marshalPrincipal(cred.Server, cred.ServerRealm, version)...)

	// Key type (2 bytes)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[:2], uint16(cred.Key.KeyType))
	buf = append(buf, tmp[:2]...)

	// Key data
	binary.BigEndian.PutUint32(tmp, uint32(len(cred.Key.KeyValue)))
	buf = append(buf, tmp...)
	buf = append(buf, cred.Key.KeyValue...)

	// Times
	binary.BigEndian.PutUint32(tmp, uint32(cred.AuthTime.Unix()))
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint32(tmp, uint32(cred.StartTime.Unix()))
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint32(tmp, uint32(cred.EndTime.Unix()))
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint32(tmp, uint32(cred.RenewTill.Unix()))
	buf = append(buf, tmp...)

	// is_skey
	if cred.IsSKey {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Ticket flags
	if len(cred.TicketFlags.Bytes) >= 4 {
		buf = append(buf, cred.TicketFlags.Bytes[:4]...)
	} else {
		flags := make([]byte, 4)
		copy(flags, cred.TicketFlags.Bytes)
		buf = append(buf, flags...)
	}

	// Addresses
	binary.BigEndian.PutUint32(tmp, uint32(len(cred.Addresses)))
	buf = append(buf, tmp...)
	for _, addr := range cred.Addresses {
		binary.BigEndian.PutUint16(tmp[:2], uint16(addr.AddrType))
		buf = append(buf, tmp[:2]...)
		binary.BigEndian.PutUint32(tmp, uint32(len(addr.Address)))
		buf = append(buf, tmp...)
		buf = append(buf, addr.Address...)
	}

	// Auth data
	binary.BigEndian.PutUint32(tmp, uint32(len(cred.AuthData)))
	buf = append(buf, tmp...)
	for _, ad := range cred.AuthData {
		binary.BigEndian.PutUint16(tmp[:2], uint16(ad.ADType))
		buf = append(buf, tmp[:2]...)
		binary.BigEndian.PutUint32(tmp, uint32(len(ad.ADData)))
		buf = append(buf, tmp...)
		buf = append(buf, ad.ADData...)
	}

	// Ticket
	binary.BigEndian.PutUint32(tmp, uint32(len(cred.Ticket)))
	buf = append(buf, tmp...)
	buf = append(buf, cred.Ticket...)

	// Second ticket
	binary.BigEndian.PutUint32(tmp, uint32(len(cred.SecondTicket)))
	buf = append(buf, tmp...)
	buf = append(buf, cred.SecondTicket...)

	return buf
}

// isNativeEndianLittle returns true if the native byte order is little-endian
func isNativeEndianLittle() bool {
	var x = 0x01234567
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)
	return bp[0] == 0x67
}