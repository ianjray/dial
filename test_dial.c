#include "dial.h"

#include <arpa/inet.h>
#include <assert.h>
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
    int server = -1;
    int client;
    char buf[8];
    ssize_t ret;
    fd_set fds_;
    fd_set set;

    printf("roundtrip(%s, %s, %s)\n", protname, hostname, servname);

    server = net_listen(protname, hostname, servname);
    if (server < 0) {
        perror("net_listen");
    }
    assert(server >= 0);

    client = net_dial(protname, hostname, servname);
    if (client < 0) {
        perror("net_dial");
    }
    assert(client >= 0);

    printf("\tserving %s,%s on socket %d; client socket %d\n", protname, hostname, server, client);

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x11;
    buf[1] = 0x22;
    ret = send(client, buf, 2, 0);
    printf("\tsend=%zd\n", ret);
    assert(ret == 2);

    FD_ZERO(&fds_);
    FD_SET(server, &fds_);
    set = fds_;
    ret = select(FD_SETSIZE, &set, (fd_set *)0, (fd_set *)0, NULL);
    printf("\tselect=%zd\n", ret);
    assert(ret >= 0);

    if (FD_ISSET(server, &set)) {
        int fd = -1;
        if (net_type(server) == SOCK_DGRAM) {
            fd = server;
        } else {
            int afd = accept(server, NULL, NULL);
            printf("\taccept=%d\n", afd);
            assert(afd >= 0);

            FD_ZERO(&fds_);
            FD_SET(afd, &fds_);
            set = fds_;
            ret = select(FD_SETSIZE, &set, (fd_set *)0, (fd_set *)0, NULL);
            printf("\tselect=%zd\n", ret);
            assert(ret >= 0);

            if (FD_ISSET(afd, &set)) {
                fd = afd;
            }
        }

        struct sockaddr_storage remote;
        socklen_t remote_length = sizeof(remote);

        memset(buf, 0, sizeof(buf));
        ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&remote, &remote_length);
        printf("\trecvfrom=%zd (%u)\n", ret, remote_length);
        assert(ret == 2);
        assert(buf[0] == 0x11);
        assert(buf[1] == 0x22);

        // Send back to client (if address available).
        if (remote_length && (remote.ss_family != AF_UNIX || ((struct sockaddr_un *)&remote)->sun_path[0])) {
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x10;
            buf[1] = 0x20;
            buf[2] = 0x30;
            ret = sendto(fd, buf, 3, 0, (struct sockaddr *)&remote, remote_length);
            printf("\tsendto=%zd\n", ret);
            assert(ret == 3);

            memset(buf, 0, sizeof(buf));
            ret = recv(client, buf, sizeof(buf), 0);
            printf("\trecv=%zd\n", ret);
            assert(ret == 3);
            assert(buf[0] == 0x10);
            assert(buf[1] == 0x20);
            assert(buf[2] == 0x30);
        }

        if (fd >= 0 && fd != server) {
            printf("\tclose=%d\n", fd);
            close(fd);
        }
    }

    printf("\tclose=%d\n", client);
    close(client);
    printf("\tclose=%d\n", server);
    close(server);
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
    listen_fail(-EADDRINUSE, "unix",     "localhost", "foo");
    unlink("foo");

    roundtrip("unix", "", "foo");
    unlink("foo");

    roundtrip("unixgram", "", "foo");
    unlink("foo");

    roundtrip("tcp4", "localhost", "49152");
    roundtrip("tcp6", "localhost", "49153");
    roundtrip("tcp6", "::1",       "49154");
    roundtrip("udp4", "localhost", "49155");
    roundtrip("udp4", "127.0.0.1", "49156");

    free(too_long);
    too_long = NULL;
}
