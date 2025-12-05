//go:build darwin
// +build darwin

// Package main provides XPC transport for GSSCred on macOS 11+.
// This file contains the cgo bindings for communicating with the GSSCred service
// via XPC (com.apple.GSSCred) which replaced KCM on macOS Big Sur and later.
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security -framework GSS

#include <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/utsname.h>

// Check if we're running on macOS 11+ (Darwin 20+)
static int is_macos_11_or_later(void) {
    struct utsname u;
    if (uname(&u) == 0) {
        int major = atoi(u.release);
        return major >= 20; // Darwin 20 = macOS 11 (Big Sur)
    }
    return 0;
}

// GSSCred XPC service name
#define GSSCRED_SERVICE "com.apple.GSSCred"

// XPC connection handle
static xpc_connection_t gsscred_conn = NULL;
static int gsscred_debug = 0;

// Initialize connection to GSSCred
static int gsscred_connect(void) {
    if (gsscred_conn != NULL) {
        return 0; // Already connected
    }

    gsscred_conn = xpc_connection_create_mach_service(GSSCRED_SERVICE, NULL, 0);
    if (gsscred_conn == NULL) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: Failed to create XPC connection to %s\n", GSSCRED_SERVICE);
        }
        return -1;
    }

    xpc_connection_set_event_handler(gsscred_conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            if (gsscred_debug) {
                fprintf(stderr, "DEBUG: GSSCred XPC error: %s\n", xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
            }
        }
    });

    xpc_connection_resume(gsscred_conn);

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: Connected to %s\n", GSSCRED_SERVICE);
    }

    return 0;
}

// Close connection to GSSCred
static void gsscred_close(void) {
    if (gsscred_conn != NULL) {
        xpc_connection_cancel(gsscred_conn);
        gsscred_conn = NULL;
    }
}

// Set debug mode
static void gsscred_set_debug(int debug) {
    gsscred_debug = debug;
}

// Get the default (primary) cache UUID
// Returns the UUID as a string, or NULL on error
static char* gsscred_get_default_cache(void) {
    if (gsscred_connect() != 0) {
        return NULL;
    }

    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "command", "default");
    xpc_dictionary_set_string(request, "mech", "kHEIMTypeKerberos");

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: Sending GSSCred 'default' request\n");
    }

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(gsscred_conn, request);

    if (reply == NULL || xpc_get_type(reply) == XPC_TYPE_ERROR) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: GSSCred request failed\n");
        }
        return NULL;
    }

    // Get the UUID from the reply
    const void *uuid_data = xpc_dictionary_get_uuid(reply, "uuid");
    if (uuid_data == NULL) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: No UUID in GSSCred reply\n");
        }
        return NULL;
    }

    // Convert UUID to string format
    char *uuid_str = malloc(37);
    if (uuid_str == NULL) {
        return NULL;
    }

    const unsigned char *uuid = (const unsigned char *)uuid_data;
    snprintf(uuid_str, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: GSSCred default cache UUID: %s\n", uuid_str);
    }

    return uuid_str;
}

// Fetch credential data for a cache by UUID
// This uses the GSS framework to access credentials
// Returns serialized credential data, or NULL on error
// The caller must free the returned data
static unsigned char* gsscred_fetch_creds(const char *cache_name, int *out_len, int *out_err) {
    *out_len = 0;
    *out_err = 0;

    if (gsscred_connect() != 0) {
        *out_err = -1;
        return NULL;
    }

    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "command", "fetch");
    xpc_dictionary_set_string(request, "mech", "kHEIMTypeKerberos");

    // Strip any "API:" prefix from cache name
    const char *uuid_str = cache_name;
    if (strncmp(cache_name, "API:", 4) == 0) {
        uuid_str = cache_name + 4;
    }

    // Parse UUID string to bytes
    unsigned char uuid_bytes[16];
    int parsed = sscanf(uuid_str, "%2hhx%2hhx%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                        &uuid_bytes[0], &uuid_bytes[1], &uuid_bytes[2], &uuid_bytes[3],
                        &uuid_bytes[4], &uuid_bytes[5], &uuid_bytes[6], &uuid_bytes[7],
                        &uuid_bytes[8], &uuid_bytes[9], &uuid_bytes[10], &uuid_bytes[11],
                        &uuid_bytes[12], &uuid_bytes[13], &uuid_bytes[14], &uuid_bytes[15]);

    if (parsed != 16) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: Failed to parse UUID: %s (parsed %d)\n", uuid_str, parsed);
        }
        *out_err = -2;
        return NULL;
    }

    xpc_dictionary_set_uuid(request, "uuid", uuid_bytes);

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: Sending GSSCred 'fetch' request for UUID: %s\n", uuid_str);
    }

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(gsscred_conn, request);

    if (reply == NULL || xpc_get_type(reply) == XPC_TYPE_ERROR) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: GSSCred fetch request failed\n");
        }
        *out_err = -3;
        return NULL;
    }

    // Check for error in reply
    int64_t err_code = xpc_dictionary_get_int64(reply, "error");
    if (err_code != 0) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: GSSCred returned error: %lld\n", err_code);
        }
        *out_err = (int)err_code;
        return NULL;
    }

    // Get credentials data
    size_t data_len = 0;
    const void *data = xpc_dictionary_get_data(reply, "credentials", &data_len);
    if (data == NULL || data_len == 0) {
        // Try alternative key names
        data = xpc_dictionary_get_data(reply, "data", &data_len);
    }

    if (data == NULL || data_len == 0) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: No credentials data in GSSCred reply\n");
            // Print all keys in reply for debugging
            xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
                fprintf(stderr, "DEBUG: Reply key: %s, type: %s\n", key, xpc_type_get_name(xpc_get_type(value)));
                return true;
            });
        }
        *out_err = -4;
        return NULL;
    }

    unsigned char *result = malloc(data_len);
    if (result == NULL) {
        *out_err = -5;
        return NULL;
    }

    memcpy(result, data, data_len);
    *out_len = (int)data_len;

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: GSSCred returned %d bytes of credential data\n", *out_len);
    }

    return result;
}

*/
import "C"

import (
	"fmt"
	"unsafe"
)

// GSSCredTransport provides XPC communication with com.apple.GSSCred
type GSSCredTransport struct {
	debug bool
}

// NewGSSCredTransport creates a new GSSCred XPC transport
func NewGSSCredTransport() *GSSCredTransport {
	return &GSSCredTransport{}
}

// SetDebug enables or disables debug output
func (t *GSSCredTransport) SetDebug(debug bool) {
	t.debug = debug
	if debug {
		C.gsscred_set_debug(1)
	} else {
		C.gsscred_set_debug(0)
	}
}

// IsMacOS11OrLater returns true if running on macOS 11 (Big Sur) or later
func IsMacOS11OrLater() bool {
	return C.is_macos_11_or_later() != 0
}

// Connect establishes connection to GSSCred service
func (t *GSSCredTransport) Connect() error {
	result := C.gsscred_connect()
	if result != 0 {
		return fmt.Errorf("failed to connect to GSSCred service")
	}
	return nil
}

// Close closes the connection to GSSCred
func (t *GSSCredTransport) Close() error {
	C.gsscred_close()
	return nil
}

// GetDefaultCache returns the default cache name/UUID
func (t *GSSCredTransport) GetDefaultCache() (string, error) {
	cstr := C.gsscred_get_default_cache()
	if cstr == nil {
		return "", fmt.Errorf("failed to get default cache from GSSCred")
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr), nil
}

// FetchCredentials fetches credentials for the specified cache
func (t *GSSCredTransport) FetchCredentials(cacheName string) ([]byte, error) {
	cname := C.CString(cacheName)
	defer C.free(unsafe.Pointer(cname))

	var dataLen C.int
	var errCode C.int

	data := C.gsscred_fetch_creds(cname, &dataLen, &errCode)
	if data == nil {
		return nil, fmt.Errorf("failed to fetch credentials: error %d", errCode)
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), dataLen), nil
}
