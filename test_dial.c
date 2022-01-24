#include "dial.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>


static void fail(int e, char const *protname, char const *hostname, char const *servname)
{
    int r = net_dial(protname, hostname, servname);
    if (r >= 0) {
        close(r);
        printf("FAIL Unexpected success: net_dial(%s, %s, %.20s)\n", protname, hostname, servname);
    } else if (r != e) {
        printf("FAIL %s: net_dial(%s, %s, %.20s)\n", strerror(-r), protname, hostname, servname);
    } else {
        printf("PASS %s: net_dial(%s, %s, %.20s)\n", strerror(-r), protname, hostname, servname);
    }
}

static void listen_fail(int e, char const *protname, char const *hostname, char const *servname)
{
    int r = net_listen(protname, hostname, servname);
    if (r >= 0) {
        close(r);
        printf("FAIL Unexpected success: net_listen(%s, %s, %.20s)\n", protname, hostname, servname);
    } else if (r != e) {
        printf("FAIL %s: net_listen(%s, %s, %.20s)\n", strerror(-r), protname, hostname, servname);
    } else {
        printf("PASS %s: net_listen(%s, %s, %.20s)\n", strerror(-r), protname, hostname, servname);
    }
}

static int net_type(int fd)
{
    int type;
    socklen_t length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0) {
        return type;
    }
    return -errno;
}

static void roundtrip(char const *protname, char const *hostname, char const *servname)
{
    int server;

    printf("roundtrip(%s, %s, %s)\n", protname, hostname, servname);
    server = net_listen(protname, hostname, servname);
    if (server >= 0) {
        int client = net_dial(protname, hostname, servname);
        printf("  serving %s,%s on socket %d; client socket %d\n", protname, hostname, server, client);
        if (client >= 0) {
            char buf[2];
            ssize_t ret;
            fd_set fds_;
            fd_set set;

            buf[0] = 0x42;
            buf[1] = 0x2A;
            ret = send(client, buf, 2, 0);
            printf("  send %zd\n", ret);
            memset(buf, 0, sizeof(buf));

            FD_ZERO(&fds_);
            FD_SET(server, &fds_);
            set = fds_;
            select(FD_SETSIZE, &set, (fd_set *) 0, (fd_set *) 0, NULL);
            if (FD_ISSET(server, &set)) {
                int fd = -1;
                if (net_type(server) != SOCK_DGRAM) {
                    int afd = accept(server, NULL, NULL);
                    FD_SET(afd, &fds_);
                    set = fds_;
                    select(FD_SETSIZE, &set, (fd_set *) 0, (fd_set *) 0, NULL);
                    if (afd >= 0 && FD_ISSET(afd, &set)) {
                        fd = afd;
                    }
                } else {
                    fd = server;
                }
                ret = recv(fd, buf, 2, 0);
                printf("  recv %zd : ", ret);
                if (ret > 0) {
                    for (int i = 0; i < ret; ++i) {
                        if (i > 0) {
                            putchar(',');
                        }
                        printf("%x", buf[i]);
                    }
                    putchar('\n');
                }
                if (fd >= 0 && fd != server) {
                    printf("  close %d\n", fd);
                    close(fd);
                }
            }
        }
        if (client >= 0) {
            printf("  close %d\n", client);
            close(client);
        } else {
            errno = -client;
            perror("client");
        }
    }
    if (server >= 0) {
        printf("  close %d\n", server);
        close(server);
    } else {
        errno = -server;
        perror("server");
    }
}

int main(void)
{
    char *too_long = malloc(10240 + 1);
    memset(too_long, 'a', 10240);
    too_long[10240] = 0;

    // unknown protocol
    fail(-EPROTONOSUPPORT,   "err",      "localhost", "http");

    // unknown address family
    fail(-EAFNOSUPPORT,      "udp99",    "localhost", "http");

    // unknown service
    fail(-ENOTSUP,           "udp",      "localhost", "unknown");

    // ipv6 loopback address
    fail(-ENOTSUP,           "udp4",     "::1",       "49152");

    // service name is too long
    fail(-EFBIG,             "unixgram", "localhost", too_long);

    // connection refused
    fail(-ECONNREFUSED,      "tcp4",     "127.0.0.1", "49152");

    // no such file (no one listening)
    fail(-ENOENT,            "unix",     "127.0.0.1", "no such...");

    // existing file, not a socket
    system("touch foo");
    fail(-ENOTSOCK,          "unix",     "127.0.0.1", "foo");
    listen_fail(-EADDRINUSE, "unix",   "localhost", "foo");
    unlink("foo");

    roundtrip("unix", "", "foo");
    unlink("foo");

    roundtrip("unixgram", "", "foo");
    unlink("foo");

    roundtrip("tcp4", "localhost", "49152");
    roundtrip("tcp6", "localhost", "49153");
    roundtrip("tcp6", "::1",       "49154");
    roundtrip("udp",  "localhost", "49155");
    roundtrip("udp4", "127.0.0.1", "49156");

    free(too_long);
    too_long = NULL;
}
