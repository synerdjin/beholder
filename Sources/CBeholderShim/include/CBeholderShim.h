//
//  CBeholderShim.h
//  Re-exports the system C interfaces Beholder needs, plus helpers for a few
//  constructs that Swift's C importer handles badly (notably the nested anonymous
//  unions inside `struct in_sockinfo`).
//

#ifndef CBEHOLDER_SHIM_H
#define CBEHOLDER_SHIM_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

// Packet capture
#include <pcap/pcap.h>
#include <net/bpf.h>

// Process / socket attribution
#include <libproc.h>
#include <sys/proc_info.h>

// Routing table (default-route discovery)
#include <net/if.h>
#include <net/route.h>

// Address families and protocol headers
#include <netinet/in.h>
#include <arpa/inet.h>

// Historical storage
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/// `PROC_PIDPATHINFO_MAXSIZE` is defined as `(4*MAXPATHLEN)`, a compound expression that
/// Swift's macro importer cannot evaluate, so it is re-exposed here as a real constant.
/// Hardcoding 4096 on the Swift side instead would silently rot if the SDK ever changed.
static const uint32_t beholder_proc_pidpath_max_size = PROC_PIDPATHINFO_MAXSIZE;

/// A flattened view of one socket's endpoint information, extracted from
/// `struct socket_fdinfo`. Swift can technically reach these fields through the
/// imported unions, but the spelling is fragile across SDK revisions and trivially
/// easy to get wrong; doing the extraction in C keeps it honest and in one place.
typedef struct {
    /// True if the socket carries usable endpoint information.
    bool     valid;
    /// True for IPv6, false for IPv4.
    bool     is_ipv6;
    /// SOCK_STREAM-ish (TCP) vs SOCK_DGRAM-ish (UDP), taken from soi_kind.
    bool     is_tcp;
    /// TCP state (TSI_S_* from netinet/tcp_fsm.h); 0 for UDP.
    int32_t  tcp_state;
    /// Host byte order. The kernel reports these in network order; we convert here
    /// so no caller has to remember to.
    uint16_t local_port;
    uint16_t remote_port;
    /// Network byte order, 4 bytes used for IPv4 and 16 for IPv6.
    uint8_t  local_addr[16];
    uint8_t  remote_addr[16];
} beholder_socket_endpoint;

/// Extracts endpoint information for a single file descriptor of a process.
/// Returns true when `out` was populated with a usable IPv4/IPv6 TCP or UDP socket.
/// Returns false for every other descriptor kind, which is the common case.
bool beholder_socket_endpoint_for_fd(pid_t pid, int32_t fd, beholder_socket_endpoint *out);

#ifdef __cplusplus
}
#endif

#endif /* CBEHOLDER_SHIM_H */
