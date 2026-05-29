/*
 * Socket test target.
 *
 * Opens one TCP listen socket on a random port and one Unix domain socket,
 * then prints connection details for the test suite to verify against the
 * captured sockets JSON.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "idle_loop.h"
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void)
{
    /* ---- TCP listen socket ---- */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) { perror("socket tcp"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* OS assigns a free port */

    if (bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind tcp"); return 1;
    }
    if (listen(tcp_fd, 1) < 0) { perror("listen"); return 1; }

    socklen_t slen = sizeof(addr);
    getsockname(tcp_fd, (struct sockaddr *)&addr, &slen);
    int tcp_port = ntohs(addr.sin_port);

    /* ---- Unix domain socket ---- */
    char unix_path[108];
    snprintf(unix_path, sizeof(unix_path), "/tmp/qcore_test_%d.sock", getpid());

    int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_fd < 0) { perror("socket unix"); return 1; }

    struct sockaddr_un uaddr;
    memset(&uaddr, 0, sizeof(uaddr));
    uaddr.sun_family = AF_UNIX;
    strncpy(uaddr.sun_path, unix_path, sizeof(uaddr.sun_path) - 1);

    if (bind(unix_fd, (struct sockaddr *)&uaddr, sizeof(uaddr)) < 0) {
        perror("bind unix"); return 1;
    }
    if (listen(unix_fd, 1) < 0) { perror("listen unix"); return 1; }

    printf("ready pid=%d tcp_port=%d unix_path=%s\n",
           getpid(), tcp_port, unix_path);
    fflush(stdout);

    qcore_idle_loop();

    close(tcp_fd);
    close(unix_fd);
    unlink(unix_path);
}
