//go:build darwin
// +build darwin

// Package main provides a KCM (Kerberos Credential Manager) client implementation
// for macOS. This is a Go port of the MIT Kerberos cc_kcm.c implementation.
//
// The KCM protocol is used on macOS to communicate with the system's credential
// cache daemon via Mach RPC.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KCM Protocol constants
const (
	// Protocol version
	kcmProtocolVersionMajor = 2
	kcmProtocolVersionMinor = 0

	// UUID length in bytes
	kcmUUIDLen = 16

	// Maximum reply size (10 MB)
	maxReplySize = 10 * 1024 * 1024

	// Maximum in-band size for Mach RPC
	maxInbandSize = 2048

	// Default Mach service name for KCM on macOS
	defaultKCMMachService = "org.h5l.kcm"
)

// KCM operation codes (opcodes)
type kcmOpcode uint16

const (
	kcmOpNoop             kcmOpcode = 0
	kcmOpGetName          kcmOpcode = 1
	kcmOpResolve          kcmOpcode = 2
	kcmOpGenNew           kcmOpcode = 3
	kcmOpInitialize       kcmOpcode = 4
	kcmOpDestroy          kcmOpcode = 5
	kcmOpStore            kcmOpcode = 6
	kcmOpRetrieve         kcmOpcode = 7
	kcmOpGetPrincipal     kcmOpcode = 8
	kcmOpGetCredUUIDList  kcmOpcode = 9
	kcmOpGetCredByUUID    kcmOpcode = 10
	kcmOpRemoveCred       kcmOpcode = 11
	kcmOpSetFlags         kcmOpcode = 12
	kcmOpChown            kcmOpcode = 13
	kcmOpChmod            kcmOpcode = 14
	kcmOpGetInitialTicket kcmOpcode = 15
	kcmOpGetTicket        kcmOpcode = 16
	kcmOpMoveCache        kcmOpcode = 17
	kcmOpGetCacheUUIDList kcmOpcode = 18
	kcmOpGetCacheByUUID   kcmOpcode = 19
	kcmOpGetDefaultCache  kcmOpcode = 20
	kcmOpSetDefaultCache  kcmOpcode = 21
	kcmOpGetKDCOffset     kcmOpcode = 22
	kcmOpSetKDCOffset     kcmOpcode = 23
	kcmOpGetCredList      kcmOpcode = 24
	kcmOpReplace          kcmOpcode = 25
)

// KCM ticket cache flags (Heimdal compatible)
const (
	kcmTCMatchTimes       = 1 << 0
	kcmTCMatchIsSKey      = 1 << 1
	kcmTCMatchFlags       = 1 << 2
	kcmTCMatchTimesExact  = 1 << 3
	kcmTCMatchFlagsExact  = 1 << 4
	kcmTCMatchAuthdata    = 1 << 5
	kcmTCMatchSrvNameonly = 1 << 6
	kcmTCMatch2ndTkt      = 1 << 7
	kcmTCMatchKeytype     = 1 << 8
	kcmGCCached           = 1 << 16 // Don't make TGS request
)

// KCM error codes
var (
	errKCMMalformedReply = errors.New("kcm: malformed reply")
	errKCMCacheNotFound  = errors.New("kcm: cache not found")
)

// kcmTransport is the interface for KCM communication backends
type kcmTransport interface {
	Connect() error
	Close() error
	Call(request []byte) ([]byte, error)
}

// kcmRequest builds a KCM protocol request
type kcmRequest struct {
	buf bytes.Buffer
}

// kcmReply parses a KCM protocol reply
type kcmReply struct {
	data []byte
	pos  int
}

// darwinCCache implements CCache for macOS using KCM
type darwinCCache struct {
	transport kcmTransport
	mu        sync.Mutex
}

// darwinCCacheHandle implements CCacheHandle for macOS using KCM
type darwinCCacheHandle struct {
	client *darwinCCache
	name   string
	mu     sync.Mutex
}

// newPlatformCCache creates a new KCM-based credential cache for macOS
func newPlatformCCache() (CCache, error) {
	cc := &darwinCCache{}

	transport := NewMachTransport(defaultKCMMachService)
	if err := transport.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to KCM: %w", err)
	}

	cc.transport = transport
	return cc, nil
}

// Close closes the KCM client connection
func (c *darwinCCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.transport != nil {
		return c.transport.Close()
	}
	return nil
}

// call sends a request to KCM and returns the reply
func (c *darwinCCache) call(req *kcmRequest) (*kcmReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := c.transport.Call(req.buf.Bytes())
	if err != nil {
		return nil, err
	}

	reply := &kcmReply{data: data}

	// Read and check the status code
	code, err := reply.readUint32()
	if err != nil {
		return nil, errKCMMalformedReply
	}
	if code != 0 {
		return nil, mapKCMError(code)
	}

	return reply, nil
}

// mapKCMError maps a KCM error code to a Go error
func mapKCMError(code uint32) error {
	switch code {
	case 0:
		return nil
	default:
		return fmt.Errorf("kcm error: %d", code)
	}
}

// GetDefaultCacheName returns the name of the default credential cache
func (c *darwinCCache) GetDefaultCacheName() (string, error) {
	req := newKCMRequest(kcmOpGetDefaultCache, "")
	reply, err := c.call(req)
	if err != nil {
		return "", err
	}
	return reply.readString()
}

// SetDefaultCache sets the default credential cache
func (c *darwinCCache) SetDefaultCache(name string) error {
	req := newKCMRequest(kcmOpSetDefaultCache, name)
	_, err := c.call(req)
	return err
}

// ListCaches returns a list of available cache names
func (c *darwinCCache) ListCaches() ([]string, error) {
	req := newKCMRequest(kcmOpGetCacheUUIDList, "")
	reply, err := c.call(req)
	if err != nil {
		return nil, err
	}

	uuids, err := reply.readUUIDList()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(uuids))
	for _, uuid := range uuids {
		req := newKCMRequest(kcmOpGetCacheByUUID, "")
		req.writeBytes(uuid)

		reply, err := c.call(req)
		if err != nil {
			continue
		}

		name, err := reply.readString()
		if err != nil {
			continue
		}
		names = append(names, name)
	}

	return names, nil
}

// OpenCache opens a credential cache by name (empty string for default)
func (c *darwinCCache) OpenCache(name string) (CCacheHandle, error) {
	if name == "" {
		var err error
		name, err = c.GetDefaultCacheName()
		if err != nil {
			return nil, err
		}
	}

	return &darwinCCacheHandle{
		client: c,
		name:   name,
	}, nil
}

// CreateCache creates a new credential cache with a unique name
func (c *darwinCCache) CreateCache() (CCacheHandle, error) {
	req := newKCMRequest(kcmOpGenNew, "")
	reply, err := c.call(req)
	if err != nil {
		return nil, err
	}

	name, err := reply.readString()
	if err != nil {
		return nil, err
	}

	return &darwinCCacheHandle{
		client: c,
		name:   name,
	}, nil
}

// Name returns the name of the cache
func (h *darwinCCacheHandle) Name() string {
	return h.name
}

// Close closes this cache handle (no-op for KCM)
func (h *darwinCCacheHandle) Close() error {
	return nil
}

// Initialize initializes the cache with a principal
func (h *darwinCCacheHandle) Initialize(principal types.PrincipalName, realm string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpInitialize, h.name)
	req.writePrincipal(principal, realm)

	_, err := h.client.call(req)
	return err
}

// Destroy destroys the credential cache
func (h *darwinCCacheHandle) Destroy() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpDestroy, h.name)
	_, err := h.client.call(req)
	return err
}

// GetPrincipal returns the default principal of the cache
func (h *darwinCCacheHandle) GetPrincipal() (types.PrincipalName, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpGetPrincipal, h.name)
	reply, err := h.client.call(req)
	if err != nil {
		return types.PrincipalName{}, "", err
	}

	if len(reply.data)-reply.pos == 0 {
		return types.PrincipalName{}, "", ErrCacheNotFound
	}

	return reply.readPrincipal()
}

// Store stores a credential in the cache
func (h *darwinCCacheHandle) Store(cred *Credential) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpStore, h.name)
	req.writeCredential(cred)

	_, err := h.client.call(req)
	return err
}

// Retrieve retrieves a credential matching the server principal
func (h *darwinCCacheHandle) Retrieve(server types.PrincipalName, serverRealm string) (*Credential, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpRetrieve, h.name)
	req.writeUint32(kcmGCCached)
	req.writeMatchCred(server, serverRealm)

	reply, err := h.client.call(req)
	if err != nil {
		return nil, err
	}

	return reply.readCredential()
}

// GetCredentials returns all credentials in the cache
func (h *darwinCCacheHandle) GetCredentials() ([]*Credential, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Try GET_CRED_LIST first
	req := newKCMRequest(kcmOpGetCredList, h.name)
	reply, err := h.client.call(req)
	if err == nil {
		return reply.readCredList()
	}

	// Fall back to GET_CRED_UUID_LIST
	req = newKCMRequest(kcmOpGetCredUUIDList, h.name)
	reply, err = h.client.call(req)
	if err != nil {
		return nil, err
	}

	uuids, err := reply.readUUIDList()
	if err != nil {
		return nil, err
	}

	// Fetch each credential by UUID
	creds := make([]*Credential, 0, len(uuids))
	for _, uuid := range uuids {
		req := newKCMRequest(kcmOpGetCredByUUID, h.name)
		req.writeBytes(uuid)

		reply, err := h.client.call(req)
		if err != nil {
			continue
		}

		cred, err := reply.readCredential()
		if err != nil {
			continue
		}
		creds = append(creds, cred)
	}

	return creds, nil
}

// RemoveCredential removes a credential from the cache
func (h *darwinCCacheHandle) RemoveCredential(server types.PrincipalName, serverRealm string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := newKCMRequest(kcmOpRemoveCred, h.name)
	req.writeUint32(0) // flags
	req.writeMatchCred(server, serverRealm)

	_, err := h.client.call(req)
	return err
}

// newKCMRequest creates a new KCM request
func newKCMRequest(opcode kcmOpcode, cacheName string) *kcmRequest {
	req := &kcmRequest{}

	// Write protocol version and opcode
	req.buf.WriteByte(kcmProtocolVersionMajor)
	req.buf.WriteByte(kcmProtocolVersionMinor)
	req.writeUint16(uint16(opcode))

	// Write cache name if provided
	if cacheName != "" {
		req.writeString(cacheName)
	}

	return req
}

// writeUint16 writes a 16-bit big-endian integer
func (r *kcmRequest) writeUint16(v uint16) {
	binary.Write(&r.buf, binary.BigEndian, v)
}

// writeUint32 writes a 32-bit big-endian integer
func (r *kcmRequest) writeUint32(v uint32) {
	binary.Write(&r.buf, binary.BigEndian, v)
}

// writeString writes a null-terminated string
func (r *kcmRequest) writeString(s string) {
	r.buf.WriteString(s)
	r.buf.WriteByte(0)
}

// writeBytes writes raw bytes
func (r *kcmRequest) writeBytes(b []byte) {
	r.buf.Write(b)
}

// writePrincipal writes a Kerberos principal in KCM format
func (r *kcmRequest) writePrincipal(princ types.PrincipalName, realm string) {
	// Name type
	r.writeUint32(uint32(princ.NameType))

	// Number of components
	r.writeUint32(uint32(len(princ.NameString)))

	// Realm
	r.writeUint32(uint32(len(realm)))
	r.buf.WriteString(realm)

	// Components
	for _, comp := range princ.NameString {
		r.writeUint32(uint32(len(comp)))
		r.buf.WriteString(comp)
	}
}

// writeCredential writes a credential in KCM format
func (r *kcmRequest) writeCredential(cred *Credential) {
	// Client principal
	r.writePrincipal(cred.Client, cred.ClientRealm)

	// Server principal
	r.writePrincipal(cred.Server, cred.ServerRealm)

	// Encryption key
	r.writeUint16(uint16(cred.Key.KeyType))
	r.writeUint32(uint32(len(cred.Key.KeyValue)))
	r.buf.Write(cred.Key.KeyValue)

	// Times
	r.writeUint32(uint32(cred.AuthTime.Unix()))
	r.writeUint32(uint32(cred.StartTime.Unix()))
	r.writeUint32(uint32(cred.EndTime.Unix()))
	r.writeUint32(uint32(cred.RenewTill.Unix()))

	// is_skey
	if cred.IsSKey {
		r.buf.WriteByte(1)
	} else {
		r.buf.WriteByte(0)
	}

	// Ticket flags (4 bytes)
	if len(cred.TicketFlags.Bytes) >= 4 {
		r.buf.Write(cred.TicketFlags.Bytes[:4])
	} else {
		flags := make([]byte, 4)
		copy(flags, cred.TicketFlags.Bytes)
		r.buf.Write(flags)
	}

	// Addresses
	r.writeUint32(uint32(len(cred.Addresses)))
	for _, addr := range cred.Addresses {
		r.writeUint16(uint16(addr.AddrType))
		r.writeUint32(uint32(len(addr.Address)))
		r.buf.Write(addr.Address)
	}

	// Auth data
	r.writeUint32(uint32(len(cred.AuthData)))
	for _, ad := range cred.AuthData {
		r.writeUint16(uint16(ad.ADType))
		r.writeUint32(uint32(len(ad.ADData)))
		r.buf.Write(ad.ADData)
	}

	// Ticket
	r.writeUint32(uint32(len(cred.Ticket)))
	r.buf.Write(cred.Ticket)

	// Second ticket
	r.writeUint32(uint32(len(cred.SecondTicket)))
	r.buf.Write(cred.SecondTicket)
}

// writeMatchCred writes a match credential structure
func (r *kcmRequest) writeMatchCred(server types.PrincipalName, serverRealm string) {
	r.writePrincipal(server, serverRealm)
}

// readUint16 reads a 16-bit big-endian integer
func (r *kcmReply) readUint16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, errKCMMalformedReply
	}
	v := binary.BigEndian.Uint16(r.data[r.pos:])
	r.pos += 2
	return v, nil
}

// readUint32 reads a 32-bit big-endian integer
func (r *kcmReply) readUint32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, errKCMMalformedReply
	}
	v := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

// readString reads a null-terminated string
func (r *kcmReply) readString() (string, error) {
	end := bytes.IndexByte(r.data[r.pos:], 0)
	if end < 0 {
		return "", errKCMMalformedReply
	}
	s := string(r.data[r.pos : r.pos+end])
	r.pos += end + 1
	return s, nil
}

// readBytes reads a specified number of bytes
func (r *kcmReply) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, errKCMMalformedReply
	}
	b := make([]byte, n)
	copy(b, r.data[r.pos:r.pos+n])
	r.pos += n
	return b, nil
}

// readData reads a length-prefixed byte array
func (r *kcmReply) readData() ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	return r.readBytes(int(length))
}

// readPrincipal reads a Kerberos principal
func (r *kcmReply) readPrincipal() (types.PrincipalName, string, error) {
	nameType, err := r.readUint32()
	if err != nil {
		return types.PrincipalName{}, "", err
	}

	numComponents, err := r.readUint32()
	if err != nil {
		return types.PrincipalName{}, "", err
	}

	realmLen, err := r.readUint32()
	if err != nil {
		return types.PrincipalName{}, "", err
	}

	realmBytes, err := r.readBytes(int(realmLen))
	if err != nil {
		return types.PrincipalName{}, "", err
	}
	realm := string(realmBytes)

	components := make([]string, numComponents)
	for i := uint32(0); i < numComponents; i++ {
		compLen, err := r.readUint32()
		if err != nil {
			return types.PrincipalName{}, "", err
		}
		compBytes, err := r.readBytes(int(compLen))
		if err != nil {
			return types.PrincipalName{}, "", err
		}
		components[i] = string(compBytes)
	}

	princ := types.PrincipalName{
		NameType:   int32(nameType),
		NameString: components,
	}

	return princ, realm, nil
}

// readCredential reads a credential from the reply
func (r *kcmReply) readCredential() (*Credential, error) {
	cred := &Credential{}

	var err error

	// Client principal
	cred.Client, cred.ClientRealm, err = r.readPrincipal()
	if err != nil {
		return nil, err
	}

	// Server principal
	cred.Server, cred.ServerRealm, err = r.readPrincipal()
	if err != nil {
		return nil, err
	}

	// Encryption key
	keyType, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	keyValue, err := r.readData()
	if err != nil {
		return nil, err
	}
	cred.Key = types.EncryptionKey{
		KeyType:  int32(keyType),
		KeyValue: keyValue,
	}

	// Times
	authTime, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.AuthTime = time.Unix(int64(authTime), 0)

	startTime, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.StartTime = time.Unix(int64(startTime), 0)

	endTime, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.EndTime = time.Unix(int64(endTime), 0)

	renewTill, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.RenewTill = time.Unix(int64(renewTill), 0)

	// is_skey
	isSKey, err := r.readBytes(1)
	if err != nil {
		return nil, err
	}
	cred.IsSKey = isSKey[0] != 0

	// Ticket flags
	flagBytes, err := r.readBytes(4)
	if err != nil {
		return nil, err
	}
	cred.TicketFlags = asn1.BitString{
		Bytes:     flagBytes,
		BitLength: 32,
	}

	// Addresses
	numAddrs, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.Addresses = make([]types.HostAddress, numAddrs)
	for i := uint32(0); i < numAddrs; i++ {
		addrType, err := r.readUint16()
		if err != nil {
			return nil, err
		}
		addrData, err := r.readData()
		if err != nil {
			return nil, err
		}
		cred.Addresses[i] = types.HostAddress{
			AddrType: int32(addrType),
			Address:  addrData,
		}
	}

	// Auth data
	numAuthData, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	cred.AuthData = make([]types.AuthorizationDataEntry, numAuthData)
	for i := uint32(0); i < numAuthData; i++ {
		adType, err := r.readUint16()
		if err != nil {
			return nil, err
		}
		adData, err := r.readData()
		if err != nil {
			return nil, err
		}
		cred.AuthData[i] = types.AuthorizationDataEntry{
			ADType: int32(adType),
			ADData: adData,
		}
	}

	// Ticket
	cred.Ticket, err = r.readData()
	if err != nil {
		return nil, err
	}

	// Second ticket
	cred.SecondTicket, err = r.readData()
	if err != nil {
		return nil, err
	}

	return cred, nil
}

// readUUIDList reads a list of UUIDs from the reply
func (r *kcmReply) readUUIDList() ([][]byte, error) {
	remaining := len(r.data) - r.pos
	if remaining%kcmUUIDLen != 0 {
		return nil, errKCMMalformedReply
	}

	count := remaining / kcmUUIDLen
	uuids := make([][]byte, count)

	for i := 0; i < count; i++ {
		uuid, err := r.readBytes(kcmUUIDLen)
		if err != nil {
			return nil, err
		}
		uuids[i] = uuid
	}

	return uuids, nil
}

// readCredList reads a list of credentials from the reply
func (r *kcmReply) readCredList() ([]*Credential, error) {
	count, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	creds := make([]*Credential, count)
	for i := uint32(0); i < count; i++ {
		// Read credential length
		credLen, err := r.readUint32()
		if err != nil {
			return nil, err
		}

		// Read credential data
		credData, err := r.readBytes(int(credLen))
		if err != nil {
			return nil, err
		}

		// Parse credential
		credReply := &kcmReply{data: credData}
		cred, err := credReply.readCredential()
		if err != nil {
			return nil, err
		}
		creds[i] = cred
	}

	return creds, nil
}