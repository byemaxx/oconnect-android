/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int set_tun(const char *name, int up) {
    pid_t child = fork();
    if (child == 0) {
        if (up) {
            execl("/system/bin/ip", "ip", "link", "set", "dev", name, "up", (char *)NULL);
        } else {
            execl("/system/bin/ip", "ip", "-4", "addr", "add", "198.18.240.17/32",
                  "dev", name, (char *)NULL);
        }
        _exit(127);
    }
    int status;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status)
            && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (argc != 3 || strlen(argv[1]) >= sizeof(address.sun_path) - 1) return 2;
    int tun = open("/dev/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    struct ifreq device = {.ifr_flags = IFF_TUN | IFF_NO_PI, .ifr_name = "octestvpn"};
    if (tun < 0 || ioctl(tun, TUNSETIFF, &device) ||
        set_tun(device.ifr_name, 0) || set_tun(device.ifr_name, 1) ||
        setuid(29001)) {
        perror("set up test TUN");
        return 1;
    }
    memcpy(address.sun_path + 1, argv[1], strlen(argv[1]));
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(argv[1]);
    if (sock < 0 || connect(sock, (struct sockaddr *)&address, length)) {
        perror("connect test broker");
        return 1;
    }
    char byte = 1;
    struct iovec payload = {.iov_base = &byte, .iov_len = 1};
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr msg = {.msg_iov = &payload, .msg_iovlen = 1,
        .msg_control = ancillary.buf, .msg_controllen = sizeof(ancillary.buf)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &tun, sizeof(tun));
    if (sendmsg(sock, &msg, 0) != 1) return 1;
    ssize_t received = read(sock, &byte, 1);
    if (!strcmp(argv[2], "failure")) return received == 0 ? 0 : 1;
    if (received != 1 || byte != 1) return 1;
    puts("Android TUN descriptor accepted");
    sleep(4);
    return shutdown(sock, SHUT_WR) == 0 && read(sock, &byte, 1) == 0 ? 0 : 1;
}
