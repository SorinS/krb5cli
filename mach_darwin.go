//go:build darwin
// +build darwin

// Package main provides Mach RPC transport for KCM on macOS.
// This file contains the cgo bindings for communicating with the KCM daemon
// via Mach IPC (Inter-Process Communication).
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security

#include <mach/mach.h>
#include <mach/message.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <string.h>

// Maximum in-band data size for KCM Mach RPC
#define KCM_MAX_INBAND_SIZE 2048

// KCM Mach message IDs
#define KCM_MACH_MSG_ID_REQUEST 1
#define KCM_MACH_MSG_ID_REPLY   2

// Request message structure for in-band data
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool_request;  // out-of-line request data
    NDR_record_t NDR;
    mach_msg_type_number_t inband_request_size;
    char inband_request[KCM_MAX_INBAND_SIZE];
    mach_msg_type_number_t ool_request_size;
} kcm_request_msg_t;

// Reply message structure
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool_reply;  // out-of-line reply data
    NDR_record_t NDR;
    int32_t return_code;
    mach_msg_type_number_t inband_reply_size;
    char inband_reply[KCM_MAX_INBAND_SIZE];
    mach_msg_type_number_t ool_reply_size;
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
                  int32_t *return_code_out) {
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
    req.header.msgh_id = KCM_MACH_MSG_ID_REQUEST;

    req.body.msgh_descriptor_count = 1;
    req.NDR = NDR_record;

    // Determine if we should use in-band or out-of-line data
    if (request_len <= KCM_MAX_INBAND_SIZE) {
        // Use in-band data
        req.inband_request_size = (mach_msg_type_number_t)request_len;
        memcpy(req.inband_request, request_data, request_len);
        req.ool_request_size = 0;
        req.ool_request.address = NULL;
        req.ool_request.size = 0;
        req.ool_request.deallocate = FALSE;
        req.ool_request.copy = MACH_MSG_VIRTUAL_COPY;
        req.ool_request.type = MACH_MSG_OOL_DESCRIPTOR;
    } else {
        // Use out-of-line data
        req.inband_request_size = 0;
        req.ool_request_size = (mach_msg_type_number_t)request_len;
        req.ool_request.address = (void *)request_data;
        req.ool_request.size = (mach_msg_size_t)request_len;
        req.ool_request.deallocate = FALSE;
        req.ool_request.copy = MACH_MSG_VIRTUAL_COPY;
        req.ool_request.type = MACH_MSG_OOL_DESCRIPTOR;
    }

    req.header.msgh_size = sizeof(req) - sizeof(reply.trailer);

    // Send request and receive reply
    kr = mach_msg(&req.header,
                  MACH_SEND_MSG | MACH_RCV_MSG,
                  req.header.msgh_size,
                  sizeof(reply),
                  req.header.msgh_local_port,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // Extract return code
    *return_code_out = reply.return_code;

    // Extract reply data
    const void *data;
    size_t len;

    if (reply.ool_reply_size > 0) {
        // Out-of-line reply
        data = reply.ool_reply.address;
        len = reply.ool_reply_size;
    } else {
        // In-band reply
        data = reply.inband_reply;
        len = reply.inband_reply_size;
    }

    if (len > 0) {
        *reply_data_out = malloc(len);
        if (*reply_data_out == NULL) {
            // Clean up OOL data if present
            if (reply.ool_reply_size > 0 && reply.ool_reply.address != NULL) {
                vm_deallocate(mach_task_self(),
                             (vm_address_t)reply.ool_reply.address,
                             reply.ool_reply_size);
            }
            return -2;
        }
        memcpy(*reply_data_out, data, len);
        *reply_len_out = len;
    }

    // Clean up OOL data if present
    if (reply.ool_reply_size > 0 && reply.ool_reply.address != NULL) {
        vm_deallocate(mach_task_self(),
                     (vm_address_t)reply.ool_reply.address,
                     reply.ool_reply_size);
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

	result := C.kcm_mach_call(
		t.port,
		unsafe.Pointer(&request[0]),
		C.size_t(len(request)),
		&replyData,
		&replyLen,
		&returnCode,
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
		)

		if result != 0 {
			return nil, fmt.Errorf("KCM RPC failed after reconnect: %d", result)
		}
	} else if result != 0 {
		return nil, fmt.Errorf("KCM RPC failed: %d", result)
	}

	// Copy the reply data to Go memory and free the C memory
	var reply []byte
	if replyLen > 0 {
		reply = C.GoBytes(replyData, C.int(replyLen))
		C.free(replyData)
	}

	return reply, nil
}