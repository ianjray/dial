#include "dial.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>


/// @brief Parse protocol version.
/// @return int AF_UNSPEC, AF_INET, or AF_INET6, or negative on error.
static int parse_version(char const *version)
{
    if (version) {
        if (!*version) {
            return AF_UNSPEC;
        } else if (!strcmp(version, "4")) {
            return AF_INET;
        } else if (!strcmp(version, "6")) {
            return AF_INET6;
        }
    }

    return -1;
}

/// @brief Skip prefix.
/// @return pointer To skipped prefix, or NULL if string does not begin with @c prefix.
static char const *skip_prefix(char const *s, char const *prefix)
{
    size_t len = strlen(prefix);
    if (strncmp(s, prefix, len) == 0) {
        return s + len;
    }

    return NULL;
}

struct info {
    /// Socket file descriptor
    int fd;
    /// Socket type
    int socktype;
    /// Length of socket-address
    socklen_t addrlen;
    /// Socket-address
    struct sockaddr *addr;
};

/// @brief Map EAI_xxx to errno
/// @return int Negative errno
static int gai_to_errno(int ecode)
{
    switch (ecode) {
	case EAI_AGAIN:      // UNREACHABLE
            return -EAGAIN;  // UNREACHABLE
	case EAI_SYSTEM:     // UNREACHABLE
            return -errno;   // UNREACHABLE
        default:
            // Assume all failures are a result of socket, service, or family being unsupported.
            return -ENOTSUP;
    }
}

static struct info resolve(char const *protname, char const *hostname, char const *servname)
{
    int family = -1;
    struct info ret;
    char const *v;
    struct addrinfo hints, *res, *res0;
    int err;

    memset(&ret, 0, sizeof(ret));
    ret.fd = -EINVAL;

    if (!strcmp(protname, "unixgram")) {
        family = AF_LOCAL;
        ret.socktype = SOCK_DGRAM;
    } else if (!strcmp(protname, "unix")) {
        family = AF_LOCAL;
        ret.socktype = SOCK_STREAM;
    }

    if (family == AF_LOCAL) {
        struct sockaddr_un addr;
        size_t limit = sizeof(addr.sun_path);
        if (strlen(servname) > limit - 1) {
            ret.fd = -EFBIG;
            return ret;
        }

        ret.fd = socket(family, ret.socktype, 0);
        if (ret.fd >= 0) {
            // Fill sockaddr_un.
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = (sa_family_t)family;
            strcpy(addr.sun_path, servname);
            // Copy to sockaddr.
            ret.addrlen = sizeof(addr);
            ret.addr = malloc(ret.addrlen);
            memcpy(ret.addr, &addr, ret.addrlen);
        }
        return ret;
    }

    v = skip_prefix(protname, "udp");
    if (v) {
        family = parse_version(v);
        ret.socktype = SOCK_DGRAM;
    }

    if (!v) {
        v = skip_prefix(protname, "tcp");
        if (v) {
            family = parse_version(v);
            ret.socktype = SOCK_STREAM;
        }
    }

    if (!v) {
        ret.fd = -EPROTONOSUPPORT;
        return ret;
    }

    if (family < 0) {
        ret.fd = -EAFNOSUPPORT;
        return ret;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = ret.socktype;

    // Get a list of IP addresses and port numbers for host hostname and service servname.
    err = getaddrinfo(hostname, servname, &hints, &res0);
    if (err) {
	ret.fd = gai_to_errno(err);
        return ret;
    }

    // Return first socket that is successfully created.
    for (res = res0, ret.fd = -1; res && ret.fd < 0; res = res->ai_next) {
        ret.fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (ret.fd >= 0) {
            ret.socktype = res->ai_socktype;
            ret.addrlen = res->ai_addrlen;
            ret.addr = malloc(ret.addrlen);
            memcpy(ret.addr, res->ai_addr, ret.addrlen);
        }
    }

    freeaddrinfo(res0);

    return ret;
}

int net_dial(char const *protname, char const *hostname, char const *servname)
{
    struct info info = resolve(protname, hostname, servname);
    int r = info.fd;
    if (r >= 0) {
        if (connect(r, info.addr, info.addrlen)) {
            close(r);
            r = -errno;
        }

        free(info.addr);
    }

    return r;
}

/// @brief Set socket option SO_REUSEADDR.
/// @discussion For re-bind without TIME_WAIT problems.
/// @return int Negative errno on failure, positive otherwise.
static int reuseaddr(int fd)
{
    int reuse_addr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr))) {
        return -errno;  // UNREACHABLE
    }                   // UNREACHABLE

    return 0;
}

static const int backlog = 8;

int net_listen(char const *protname, char const *hostname, char const *servname)
{
    struct info info = resolve(protname, hostname, servname);
    int r = info.fd;
    if (r >= 0) {
        reuseaddr(r);

        if (r >= 0 && bind(r, info.addr, info.addrlen)) {
            close(r);
            r = -errno;
        }

        if (info.socktype == SOCK_STREAM) {
            if (r >= 0 && listen(r, backlog)) {
                close(r);    // UNREACHABLE
                r = -errno;  // UNREACHABLE
            }                // UNREACHABLE
        }

        free(info.addr);
    }

    return r;
}
