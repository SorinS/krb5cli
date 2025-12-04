//go:build darwin
// +build darwin

// Package main provides Mach RPC transport for KCM on macOS.
// This file contains the cgo bindings for communicating with the KCM daemon
// via Mach IPC (Inter-Process Communication).
//
// The KCM daemon on macOS uses Heimdal's kcm protocol over Mach IPC.
// The MIG (Mach Interface Generator) subsystem is "mheim_ipc" with base ID 1,
// so message IDs start at 1 for the kcm_call routine.
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security

#include <mach/mach.h>
#include <mach/message.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Maximum in-band data size for KCM Mach RPC (from Heimdal kcm.defs)
#define KCM_MAX_INBAND_SIZE 2048

// KCM MIG subsystem base ID (from MIT krb5 kcmrpc.defs)
// The subsystem is "mheim_ipc" with base ID 1
// The actual routine is kcm_call which is routine 0 in the subsystem
#define KCM_SUBSYSTEM_BASE 1
#define KCM_MSG_ID_CALL (KCM_SUBSYSTEM_BASE + 0)

// Request message structure matching Heimdal's kcm MIG definition
// This matches the __Request__kcm_call_t structure
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool_request;
    NDR_record_t NDR;
    mach_msg_type_number_t inband_request_count;
    char inband_request[KCM_MAX_INBAND_SIZE];
    mach_msg_type_number_t ool_request_count;
} kcm_request_msg_t;

// Reply message structure matching Heimdal's kcm MIG definition
// The reply can be either complex (with OOL data) or simple (in-band only)
// We use a union-like approach with a large buffer
typedef struct {
    mach_msg_header_t header;
    union {
        // Complex reply (has OOL descriptor)
        struct {
            mach_msg_body_t body;
            mach_msg_ool_descriptor_t ool_reply;
            NDR_record_t NDR;
            kern_return_t retcode;
            mach_msg_type_number_t inband_reply_count;
            char inband_reply[KCM_MAX_INBAND_SIZE];
            mach_msg_type_number_t ool_reply_count;
        } complex;
        // Simple reply (no OOL descriptor)
        struct {
            NDR_record_t NDR;
            kern_return_t retcode;
            mach_msg_type_number_t inband_reply_count;
            char inband_reply[KCM_MAX_INBAND_SIZE];
            mach_msg_type_number_t ool_reply_count;
        } simple;
        // Raw buffer for inspection
        char raw[KCM_MAX_INBAND_SIZE + 256];
    } data;
    mach_msg_trailer_t trailer;
} kcm_reply_msg_t;

// Connect to the KCM service via bootstrap
kern_return_t kcm_mach_connect(const char *service_name, mach_port_t *port_out) {
    return bootstrap_look_up(bootstrap_port, service_name, port_out);
}

// Deallocate a Mach port
kern_return_t kcm_mach_disconnect(mach_port_t port) {
    if (port != MACH_PORT_NULL) {
        return mach_port_deallocate(mach_task_self(), port);
    }
    return KERN_SUCCESS;
}

// Send a request to KCM and receive a reply
// Returns 0 on success, negative on error
// On success, reply_data and reply_len are set (caller must free reply_data)
int kcm_mach_call(mach_port_t port,
                  const void *request_data, size_t request_len,
                  void **reply_data_out, size_t *reply_len_out,
                  int32_t *return_code_out,
                  int debug) {
    kern_return_t kr;
    kcm_request_msg_t req;
    kcm_reply_msg_t reply;

    *reply_data_out = NULL;
    *reply_len_out = 0;
    *return_code_out = 0;

    memset(&req, 0, sizeof(req));
    memset(&reply, 0, sizeof(reply));

    // Set up the request message header
    req.header.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                           MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    req.header.msgh_remote_port = port;
    req.header.msgh_local_port = mig_get_reply_port();
    req.header.msgh_id = KCM_MSG_ID_CALL;

    req.body.msgh_descriptor_count = 1;
    req.NDR = NDR_record;

    // Set up the OOL descriptor (always present, even if empty)
    req.ool_request.type = MACH_MSG_OOL_DESCRIPTOR;
    req.ool_request.copy = MACH_MSG_VIRTUAL_COPY;
    req.ool_request.deallocate = FALSE;

    // Determine if we should use in-band or out-of-line data
    if (request_len <= KCM_MAX_INBAND_SIZE) {
        // Use in-band data
        req.inband_request_count = (mach_msg_type_number_t)request_len;
        memcpy(req.inband_request, request_data, request_len);
        req.ool_request_count = 0;
        req.ool_request.address = NULL;
        req.ool_request.size = 0;
    } else {
        // Use out-of-line data
        req.inband_request_count = 0;
        req.ool_request_count = (mach_msg_type_number_t)request_len;
        req.ool_request.address = (void *)request_data;
        req.ool_request.size = (mach_msg_size_t)request_len;
    }

    // Calculate message size (exclude trailer which is only in reply)
    req.header.msgh_size = sizeof(req);

    if (debug) {
        fprintf(stderr, "DEBUG: Sending mach_msg with id=%d, size=%d, request_len=%zu\n",
                req.header.msgh_id, req.header.msgh_size, request_len);
        fprintf(stderr, "DEBUG: Request bytes: ");
        for (size_t i = 0; i < request_len && i < 32; i++) {
            fprintf(stderr, "%02x ", ((unsigned char*)request_data)[i]);
        }
        fprintf(stderr, "\n");
    }

    // Send request and receive reply
    kr = mach_msg(&req.header,
                  MACH_SEND_MSG | MACH_RCV_MSG,
                  req.header.msgh_size,
                  sizeof(reply),
                  req.header.msgh_local_port,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);

    if (kr != KERN_SUCCESS) {
        if (debug) {
            fprintf(stderr, "DEBUG: mach_msg failed with kr=%d\n", kr);
        }
        *return_code_out = kr;
        return -1;
    }

    // Check if reply is complex (has descriptors) or simple
    int is_complex = (reply.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0;

    if (debug) {
        fprintf(stderr, "DEBUG: mach_msg succeeded\n");
        fprintf(stderr, "DEBUG: reply.header.msgh_id=%d, msgh_size=%d, is_complex=%d\n",
                reply.header.msgh_id, reply.header.msgh_size, is_complex);

        // Dump raw reply bytes for debugging
        size_t dump_len = reply.header.msgh_size;
        if (dump_len > 128) dump_len = 128;
        fprintf(stderr, "DEBUG: Raw reply (%zu bytes): ", dump_len);
        unsigned char *raw = (unsigned char*)&reply;
        for (size_t i = 0; i < dump_len; i++) {
            fprintf(stderr, "%02x ", raw[i]);
            if ((i + 1) % 16 == 0) fprintf(stderr, "\n                          ");
        }
        fprintf(stderr, "\n");
    }

    // Extract reply data based on whether reply is complex or simple
    const void *data = NULL;
    size_t len = 0;
    kern_return_t retcode = 0;

    if (is_complex) {
        // Complex reply with OOL descriptor
        retcode = reply.data.complex.retcode;
        if (reply.data.complex.ool_reply_count > 0 && reply.data.complex.ool_reply.address != NULL) {
            data = reply.data.complex.ool_reply.address;
            len = reply.data.complex.ool_reply_count;
        } else {
            data = reply.data.complex.inband_reply;
            len = reply.data.complex.inband_reply_count;
        }
        if (debug) {
            fprintf(stderr, "DEBUG: Complex reply: retcode=%d, inband_count=%d, ool_count=%d\n",
                    retcode, reply.data.complex.inband_reply_count, reply.data.complex.ool_reply_count);
        }
    } else {
        // Simple reply without OOL descriptor
        retcode = reply.data.simple.retcode;
        data = reply.data.simple.inband_reply;
        len = reply.data.simple.inband_reply_count;
        if (debug) {
            fprintf(stderr, "DEBUG: Simple reply: retcode=%d, inband_count=%d\n",
                    retcode, reply.data.simple.inband_reply_count);
        }
    }

    // Check the MIG return code
    if (retcode != KERN_SUCCESS) {
        *return_code_out = retcode;
        if (debug) {
            fprintf(stderr, "DEBUG: MIG retcode indicates error: %d\n", retcode);
        }
        return -3;
    }

    if (debug && len > 0) {
        fprintf(stderr, "DEBUG: Reply data (%zu bytes): ", len);
        for (size_t i = 0; i < len && i < 64; i++) {
            fprintf(stderr, "%02x ", ((unsigned char*)data)[i]);
        }
        fprintf(stderr, "\n");
    }

    if (len > 0) {
        *reply_data_out = malloc(len);
        if (*reply_data_out == NULL) {
            // Clean up OOL data if present
            if (is_complex && reply.data.complex.ool_reply_count > 0 && reply.data.complex.ool_reply.address != NULL) {
                vm_deallocate(mach_task_self(),
                             (vm_address_t)reply.data.complex.ool_reply.address,
                             reply.data.complex.ool_reply_count);
            }
            return -2;
        }
        memcpy(*reply_data_out, data, len);
        *reply_len_out = len;
    }

    // Clean up OOL data if present
    if (is_complex && reply.data.complex.ool_reply_count > 0 && reply.data.complex.ool_reply.address != NULL) {
        vm_deallocate(mach_task_self(),
                     (vm_address_t)reply.data.complex.ool_reply.address,
                     reply.data.complex.ool_reply_count);
    }

    return 0;
}

// Check if a Mach service exists
int kcm_service_exists(const char *service_name) {
    mach_port_t port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &port);
    if (kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
        return 1;
    }
    return 0;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// MachTransport implements KCMTransport using Mach RPC
type MachTransport struct {
	serviceName string
	port        C.mach_port_t
	connected   bool
	debug       bool
}

// NewMachTransport creates a new Mach RPC transport
func NewMachTransport(serviceName string) *MachTransport {
	return &MachTransport{
		serviceName: serviceName,
		port:        C.MACH_PORT_NULL,
	}
}

// Connect establishes a connection to the KCM daemon
func (t *MachTransport) Connect() error {
	if t.connected {
		return nil
	}

	cServiceName := C.CString(t.serviceName)
	defer C.free(unsafe.Pointer(cServiceName))

	var port C.mach_port_t
	kr := C.kcm_mach_connect(cServiceName, &port)
	if kr != C.KERN_SUCCESS {
		return fmt.Errorf("failed to connect to KCM service %q: bootstrap_look_up failed with %d", t.serviceName, kr)
	}

	t.port = port
	t.connected = true
	return nil
}

// Close closes the connection to the KCM daemon
func (t *MachTransport) Close() error {
	if !t.connected {
		return nil
	}

	kr := C.kcm_mach_disconnect(t.port)
	if kr != C.KERN_SUCCESS {
		return fmt.Errorf("failed to disconnect from KCM: %d", kr)
	}

	t.port = C.MACH_PORT_NULL
	t.connected = false
	return nil
}

// SetDebug enables or disables debug output
func (t *MachTransport) SetDebug(debug bool) {
	t.debug = debug
}

// Call sends a request to KCM and returns the reply
func (t *MachTransport) Call(request []byte) ([]byte, error) {
	if !t.connected {
		if err := t.Connect(); err != nil {
			return nil, err
		}
	}

	var replyData unsafe.Pointer
	var replyLen C.size_t
	var returnCode C.int32_t

	debugFlag := C.int(0)
	if t.debug {
		debugFlag = C.int(1)
	}

	result := C.kcm_mach_call(
		t.port,
		unsafe.Pointer(&request[0]),
		C.size_t(len(request)),
		&replyData,
		&replyLen,
		&returnCode,
		debugFlag,
	)

	if result == -1 {
		// Connection error - try to reconnect once
		t.connected = false
		if err := t.Connect(); err != nil {
			return nil, fmt.Errorf("KCM RPC failed and reconnect failed: %w", err)
		}

		result = C.kcm_mach_call(
			t.port,
			unsafe.Pointer(&request[0]),
			C.size_t(len(request)),
			&replyData,
			&replyLen,
			&returnCode,
			debugFlag,
		)

		if result != 0 {
			return nil, fmt.Errorf("KCM RPC failed after reconnect: %d", result)
		}
	} else if result != 0 {
		return nil, fmt.Errorf("KCM RPC failed: %d (return_code=%d)", result, returnCode)
	}

	// Copy the reply data to Go memory and free the C memory
	var reply []byte
	if replyLen > 0 {
		reply = C.GoBytes(replyData, C.int(replyLen))
		C.free(replyData)
	}

	return reply, nil
}

// ServiceExists checks if a Mach service exists
func ServiceExists(serviceName string) bool {
	cServiceName := C.CString(serviceName)
	defer C.free(unsafe.Pointer(cServiceName))
	return C.kcm_service_exists(cServiceName) == 1
}