#include "include/CBeholderShim.h"

#include <string.h>

bool beholder_socket_endpoint_for_fd(pid_t pid, int32_t fd, beholder_socket_endpoint *out) {
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    struct socket_fdinfo info;
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    if (size < (int)sizeof(struct socket_fdinfo)) {
        // Not a socket, or the process exited between listing its fds and this call.
        // Both are routine, not errors worth reporting.
        return false;
    }

    const struct in_sockinfo *in = NULL;
    switch (info.psi.soi_kind) {
        case SOCKINFO_TCP:
            in = &info.psi.soi_proto.pri_tcp.tcpsi_ini;
            out->is_tcp = true;
            out->tcp_state = info.psi.soi_proto.pri_tcp.tcpsi_state;
            break;
        case SOCKINFO_IN:
            in = &info.psi.soi_proto.pri_in;
            out->is_tcp = false;
            out->tcp_state = 0;
            break;
        default:
            // Unix domain sockets, kernel control sockets, etc.
            return false;
    }

    // Only AF_INET / AF_INET6 sockets describe network endpoints.
    if (info.psi.soi_family != AF_INET && info.psi.soi_family != AF_INET6) {
        return false;
    }

    // insi_vflag tells us which half of the address union is meaningful.
    // A v4-mapped socket can report both flags. Prefer the IPv4 view in that case:
    // such a socket's packets appear on the wire as IPv4, so the v4 address is what
    // the flow table must match against.
    const bool has_v6 = (in->insi_vflag & INI_IPV6) != 0;
    const bool has_v4 = (in->insi_vflag & INI_IPV4) != 0;
    if (!has_v4 && !has_v6) {
        return false;
    }
    out->is_ipv6 = has_v6 && !has_v4;

    // The kernel stores these in network byte order.
    out->local_port  = ntohs((uint16_t)in->insi_lport);
    out->remote_port = ntohs((uint16_t)in->insi_fport);

    if (out->is_ipv6) {
        memcpy(out->local_addr,  &in->insi_laddr.ina_6, 16);
        memcpy(out->remote_addr, &in->insi_faddr.ina_6, 16);
    } else {
        memcpy(out->local_addr,  &in->insi_laddr.ina_46.i46a_addr4, 4);
        memcpy(out->remote_addr, &in->insi_faddr.ina_46.i46a_addr4, 4);
    }

    out->valid = true;
    return true;
}
