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

    // Debug: print all keys in the reply
    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: GSSCred reply keys:\n");
        xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
            const char *type_name = xpc_type_get_name(xpc_get_type(value));
            fprintf(stderr, "DEBUG:   key='%s' type='%s'", key, type_name);
            if (xpc_get_type(value) == XPC_TYPE_STRING) {
                fprintf(stderr, " value='%s'", xpc_string_get_string_ptr(value));
            } else if (xpc_get_type(value) == XPC_TYPE_INT64) {
                fprintf(stderr, " value=%lld", xpc_int64_get_value(value));
            } else if (xpc_get_type(value) == XPC_TYPE_DATA) {
                fprintf(stderr, " len=%zu", xpc_data_get_length(value));
            }
            fprintf(stderr, "\n");
            return true;
        });
    }

    // Get the UUID from the reply - the key is 'default' not 'uuid'
    const void *uuid_data = xpc_dictionary_get_uuid(reply, "default");
    if (uuid_data == NULL) {
        // Try other possible key names
        uuid_data = xpc_dictionary_get_uuid(reply, "uuid");
    }
    if (uuid_data == NULL) {
        uuid_data = xpc_dictionary_get_uuid(reply, "defaultUUID");
    }
    if (uuid_data == NULL) {
        uuid_data = xpc_dictionary_get_uuid(reply, "cacheUUID");
    }

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

// ============================================================================
// GSS Framework API for credential access
// Using gss_iter_creds to iterate through credentials properly
// ============================================================================

#include <GSS/GSS.h>

// Structure to hold credential information
typedef struct {
    char *client_principal;
    char *server_principal;
    uint32_t lifetime;      // remaining lifetime in seconds
    time_t auth_time;
    time_t start_time;
    time_t end_time;
    time_t renew_till;
    int32_t key_type;
} gss_cred_info_t;

// Maximum number of credentials to collect
#define MAX_CREDS 100

// Global storage for collected credentials (used by iterator callback)
static gss_cred_info_t *g_creds = NULL;
static int g_cred_count = 0;
static int g_max_creds = 0;

// Convert gss_name_t to string
static char* gss_name_to_string(gss_name_t name) {
    if (name == GSS_C_NO_NAME) {
        return strdup("(none)");
    }

    OM_uint32 major, minor;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

    major = gss_display_name(&minor, name, &buf, NULL);
    if (major != GSS_S_COMPLETE) {
        return strdup("(error)");
    }

    char *result = strndup(buf.value, buf.length);
    gss_release_buffer(&minor, &buf);
    return result;
}

// Get credentials using GSS framework API
// Returns array of credential info structures
static int gss_get_credentials(gss_cred_info_t **out_creds, int *out_count) {
    *out_creds = NULL;
    *out_count = 0;

    // Allocate storage for credentials
    g_creds = calloc(MAX_CREDS, sizeof(gss_cred_info_t));
    if (g_creds == NULL) {
        return -1;
    }
    g_cred_count = 0;
    g_max_creds = MAX_CREDS;

    OM_uint32 minor;

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: Using gss_iter_creds to iterate credentials\n");
    }

    // Iterate over all Kerberos credentials
    // GSS_KRB5_MECHANISM is the OID for Kerberos
    gss_iter_creds(&minor, 0, GSS_KRB5_MECHANISM, ^(gss_OID mech, gss_cred_id_t cred) {
        if (cred == GSS_C_NO_CREDENTIAL || g_cred_count >= g_max_creds) {
            return;
        }

        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: Found credential %d\n", g_cred_count);
        }

        gss_cred_info_t *info = &g_creds[g_cred_count];
        memset(info, 0, sizeof(gss_cred_info_t));

        // Get the credential name (client principal)
        OM_uint32 major, min;
        gss_name_t cred_name = GSS_C_NO_NAME;
        OM_uint32 lifetime = 0;

        major = gss_inquire_cred(&min, cred, &cred_name, &lifetime, NULL, NULL);
        if (major == GSS_S_COMPLETE) {
            info->client_principal = gss_name_to_string(cred_name);
            info->lifetime = lifetime;

            // Calculate times based on lifetime
            time_t now = time(NULL);
            info->end_time = now + lifetime;
            info->start_time = now; // Approximate
            info->auth_time = now;  // Approximate

            if (gsscred_debug) {
                fprintf(stderr, "DEBUG: Credential %d: principal=%s, lifetime=%u\n",
                        g_cred_count, info->client_principal, lifetime);
            }

            if (cred_name != GSS_C_NO_NAME) {
                gss_release_name(&min, &cred_name);
            }
        } else {
            info->client_principal = strdup("(unknown)");
            if (gsscred_debug) {
                fprintf(stderr, "DEBUG: gss_inquire_cred failed: major=%u, minor=%u\n", major, min);
            }
        }

        // Server principal - for TGT it would be krbtgt/REALM@REALM
        // We can try to get this from the credential if available
        info->server_principal = strdup("krbtgt");

        g_cred_count++;
    });

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: gss_iter_creds found %d credentials\n", g_cred_count);
    }

    if (g_cred_count == 0) {
        free(g_creds);
        g_creds = NULL;
        return 0;
    }

    *out_creds = g_creds;
    *out_count = g_cred_count;
    g_creds = NULL; // Transfer ownership

    return 0;
}

// Free credential info array
static void gss_free_credentials(gss_cred_info_t *creds, int count) {
    if (creds == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(creds[i].client_principal);
        free(creds[i].server_principal);
    }
    free(creds);
}

// Get the default principal name using GSS API
static char* gss_get_default_principal(void) {
    OM_uint32 major, minor;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_name_t name = GSS_C_NO_NAME;
    char *result = NULL;

    // Acquire default credential
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred, NULL, NULL);
    if (major != GSS_S_COMPLETE) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_acquire_cred failed: major=%u, minor=%u\n", major, minor);
        }
        return NULL;
    }

    // Get the name from the credential
    major = gss_inquire_cred(&minor, cred, &name, NULL, NULL, NULL);
    if (major == GSS_S_COMPLETE && name != GSS_C_NO_NAME) {
        result = gss_name_to_string(name);
        gss_release_name(&minor, &name);
    }

    gss_release_cred(&minor, &cred);

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: Default principal: %s\n", result ? result : "(none)");
    }

    return result;
}

// Get a service ticket for the specified SPN using gss_init_sec_context
// This is the proper way to get service tickets on macOS
// Returns the SPNEGO/Kerberos token that can be used for authentication
static unsigned char* gss_get_service_ticket(const char *spn, int *out_len, int *out_err) {
    *out_len = 0;
    *out_err = 0;

    OM_uint32 major, minor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc spn_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    // Import the SPN as a GSS name
    spn_buf.value = (void*)spn;
    spn_buf.length = strlen(spn);

    major = gss_import_name(&minor, &spn_buf, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (major != GSS_S_COMPLETE) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_import_name failed: major=%u, minor=%u\n", major, minor);
        }
        *out_err = -1;
        return NULL;
    }

    if (gsscred_debug) {
        char *name_str = gss_name_to_string(target_name);
        fprintf(stderr, "DEBUG: Target name: %s\n", name_str);
        free(name_str);
    }

    // Initialize security context - this will get a service ticket from the KDC
    OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    OM_uint32 ret_flags = 0;

    major = gss_init_sec_context(
        &minor,
        GSS_C_NO_CREDENTIAL,    // Use default credential (TGT from cache)
        &ctx,
        target_name,
        GSS_KRB5_MECHANISM,     // Use Kerberos mechanism
        req_flags,
        GSS_C_INDEFINITE,       // No time limit
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_C_NO_BUFFER,        // No input token (first call)
        NULL,                   // Don't need actual mech type
        &output_token,
        &ret_flags,
        NULL                    // Don't need time_rec
    );

    gss_release_name(&minor, &target_name);

    if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_init_sec_context failed: major=%u (0x%x), minor=%u (0x%x)\n",
                    major, major, minor, minor);

            // Get GSS major status message
            OM_uint32 msg_ctx = 0;
            OM_uint32 disp_minor;
            gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;

            do {
                gss_display_status(&disp_minor, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status_string);
                fprintf(stderr, "DEBUG: GSS major error: %.*s\n", (int)status_string.length, (char*)status_string.value);
                gss_release_buffer(&disp_minor, &status_string);
            } while (msg_ctx != 0);

            // Get mechanism-specific (minor) status message - this often has the real error
            msg_ctx = 0;
            do {
                gss_display_status(&disp_minor, minor, GSS_C_MECH_CODE, GSS_KRB5_MECHANISM, &msg_ctx, &status_string);
                if (status_string.length > 0) {
                    fprintf(stderr, "DEBUG: Kerberos error: %.*s\n", (int)status_string.length, (char*)status_string.value);
                }
                gss_release_buffer(&disp_minor, &status_string);
            } while (msg_ctx != 0);
        }
        if (ctx != GSS_C_NO_CONTEXT) {
            gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
        }
        *out_err = -2;
        return NULL;
    }

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: gss_init_sec_context succeeded, output token: %zu bytes\n", output_token.length);
        fprintf(stderr, "DEBUG: Return flags: 0x%x\n", ret_flags);
    }

    // Copy the output token
    unsigned char *result = NULL;
    if (output_token.length > 0 && output_token.value != NULL) {
        result = malloc(output_token.length);
        if (result != NULL) {
            memcpy(result, output_token.value, output_token.length);
            *out_len = (int)output_token.length;
        } else {
            *out_err = -3;
        }
    }

    gss_release_buffer(&minor, &output_token);
    if (ctx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    }

    return result;
}

// Export credential to buffer using gss_export_cred
// Returns the exported credential data which contains the serialized ticket
static unsigned char* gss_export_default_cred(int *out_len, int *out_err) {
    *out_len = 0;
    *out_err = 0;

    OM_uint32 major, minor;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

    // Acquire default credential
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred, NULL, NULL);
    if (major != GSS_S_COMPLETE) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_acquire_cred failed: major=%u, minor=%u\n", major, minor);
        }
        *out_err = -1;
        return NULL;
    }

    // Export the credential
    major = gss_export_cred(&minor, cred, &token);
    gss_release_cred(&minor, &cred);

    if (major != GSS_S_COMPLETE) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_export_cred failed: major=%u, minor=%u\n", major, minor);
        }
        *out_err = -2;
        return NULL;
    }

    if (token.length == 0 || token.value == NULL) {
        if (gsscred_debug) {
            fprintf(stderr, "DEBUG: gss_export_cred returned empty token\n");
        }
        *out_err = -3;
        return NULL;
    }

    if (gsscred_debug) {
        fprintf(stderr, "DEBUG: gss_export_cred returned %zu bytes\n", token.length);
        // Print first 64 bytes for debugging
        fprintf(stderr, "DEBUG: Exported cred data: ");
        for (size_t i = 0; i < token.length && i < 64; i++) {
            fprintf(stderr, "%02x ", ((unsigned char*)token.value)[i]);
        }
        fprintf(stderr, "\n");
    }

    // Copy the data
    unsigned char *result = malloc(token.length);
    if (result == NULL) {
        gss_release_buffer(&minor, &token);
        *out_err = -4;
        return NULL;
    }

    memcpy(result, token.value, token.length);
    *out_len = (int)token.length;

    gss_release_buffer(&minor, &token);
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

// GSSCredInfo holds credential information from GSS API
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

// GetDefaultPrincipal returns the default principal using GSS API
func (t *GSSCredTransport) GetDefaultPrincipal() (string, error) {
	cstr := C.gss_get_default_principal()
	if cstr == nil {
		return "", fmt.Errorf("no default credential available")
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr), nil
}

// GetCredentials returns all credentials using GSS API
func (t *GSSCredTransport) GetCredentials() ([]GSSCredInfo, error) {
	var cCreds *C.gss_cred_info_t
	var count C.int

	result := C.gss_get_credentials(&cCreds, &count)
	if result != 0 {
		return nil, fmt.Errorf("failed to get credentials: %d", result)
	}

	if count == 0 || cCreds == nil {
		return []GSSCredInfo{}, nil
	}
	defer C.gss_free_credentials(cCreds, count)

	// Convert C array to Go slice
	creds := make([]GSSCredInfo, int(count))
	credArray := (*[1 << 20]C.gss_cred_info_t)(unsafe.Pointer(cCreds))[:count:count]

	for i := 0; i < int(count); i++ {
		creds[i] = GSSCredInfo{
			ClientPrincipal: C.GoString(credArray[i].client_principal),
			ServerPrincipal: C.GoString(credArray[i].server_principal),
			Lifetime:        uint32(credArray[i].lifetime),
			AuthTime:        int64(credArray[i].auth_time),
			StartTime:       int64(credArray[i].start_time),
			EndTime:         int64(credArray[i].end_time),
			RenewTill:       int64(credArray[i].renew_till),
			KeyType:         int32(credArray[i].key_type),
		}
	}

	return creds, nil
}

// ExportCredential exports the default credential using gss_export_cred
// This returns a serialized credential that may contain ticket and session key data
func (t *GSSCredTransport) ExportCredential() ([]byte, error) {
	var dataLen C.int
	var errCode C.int

	data := C.gss_export_default_cred(&dataLen, &errCode)
	if data == nil {
		return nil, fmt.Errorf("failed to export credential: error %d", errCode)
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), dataLen), nil
}

// GetServiceTicket obtains a service ticket for the specified SPN using gss_init_sec_context
// The SPN should be in the format "service@hostname" or "service/hostname"
// Returns the SPNEGO/Kerberos token that can be used for authentication
func (t *GSSCredTransport) GetServiceTicket(spn string) ([]byte, error) {
	cspn := C.CString(spn)
	defer C.free(unsafe.Pointer(cspn))

	var dataLen C.int
	var errCode C.int

	data := C.gss_get_service_ticket(cspn, &dataLen, &errCode)
	if data == nil {
		return nil, fmt.Errorf("failed to get service ticket: error %d", errCode)
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), dataLen), nil
}

