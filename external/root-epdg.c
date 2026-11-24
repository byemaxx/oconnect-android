/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Minimal root TUN helper for the experimental OConnect ePDG-only mode.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define IFACE "ocroot0"
#define TABLE "19270"
#define COMMENT "oconnect-root-epdg"
#define IP "/system/bin/ip"
#define IPT "/system/bin/iptables"
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }

/* Only fixed command templates and independently validated numeric arguments
 * are used. Never execute profile-supplied shell code as root. */
static int command(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0 || n >= (int)sizeof(buf)) return -1;
    int rc = system(buf);
    if (rc == -1 || !WIFEXITED(rc) || WEXITSTATUS(rc)) {
        fprintf(stderr, "command failed: %s (status %d)\n", buf, rc);
        return -1;
    }
    return 0;
}

static int parse_num(const char *s, long min, long max, long *out) {
    char *end;
    if (!s || !*s || strspn(s, "0123456789") != strlen(s)) return -1;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v < min || v > max) return -1;
    *out = v;
    return 0;
}
static int valid_v4(const char *s) {
    struct in_addr a;
    return inet_pton(AF_INET, s, &a) == 1;
}
static int public_v4(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    unsigned v = ntohl(a.s_addr), x = v >> 24, y = (v >> 16) & 255;
    return !(x == 0 || x == 10 || x == 127 || x >= 224 ||
        (x == 169 && y == 254) || (x == 172 && y >= 16 && y <= 31) ||
        (x == 192 && y == 168) || (x == 100 && y >= 64 && y <= 127));
}
static int policy_free(void) {
    char line[1024];
    FILE *fp = popen(IP " -4 rule show", "r");
    if (!fp) return 0;
    int free = 1;
    while (fgets(line, sizeof(line), fp)) {
        unsigned pref;
        if ((sscanf(line, "%u:", &pref) == 1 && (pref == 9100 || pref == 9101))
                || strstr(line, "lookup " TABLE)) free = 0;
    }
    if (pclose(fp) != 0 || !free) return 0;
    fp = popen(IP " -4 route show table " TABLE " 2>/dev/null", "r");
    if (!fp) return 0;
    free = fgets(line, sizeof(line), fp) == NULL;
    /* ip may report a missing table, which is normal before our first route. */
    pclose(fp);
    return free;
}
static int send_fd(int sock, int fd) {
    char status = 1;
    struct iovec iov = { .iov_base = &status, .iov_len = 1 };
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    return sendmsg(sock, &msg, MSG_NOSIGNAL) == 1 ? 0 : -1;
}
int main(int argc, char **argv) {
    int listener = -1, client = -1, tun = -1, result = 1;
    int route = 0, rule500 = 0, rule4500 = 0, snat = 0, input = 0, forward_in = 0, forward_out = 0;
    long uid, prefix, mtu;
    if (argc != 7 || getuid() != 0 || parse_num(argv[2], 1, 2147483647, &uid)
            || !valid_v4(argv[3]) || parse_num(argv[4], 0, 32, &prefix)
            || parse_num(argv[5], 576, 1500, &mtu) || !public_v4(argv[6])
            || !strcmp(argv[3], argv[6])) {
        fputs("Invalid root helper arguments\n", stderr); return 2;
    }
    const char *name = argv[1], *addr = argv[3], *target = argv[6];
    if (strncmp(name, "oconnect-root-", 14) || strlen(name) > 90 ||
            strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(name)) return 2;
    signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGHUP, stop); signal(SIGPIPE, SIG_IGN);
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) goto cleanup;
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    memcpy(sa.sun_path + 1, name, strlen(name));
    if (bind(listener, (struct sockaddr *)&sa,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name))) ||
            listen(listener, 1)) goto cleanup;
    struct pollfd p = { .fd = listener, .events = POLLIN };
    if (poll(&p, 1, 60000) <= 0 || stopped) goto cleanup;
    client = accept(listener, NULL, NULL);
    if (client < 0) goto cleanup;
    fcntl(client, F_SETFD, FD_CLOEXEC);
    struct ucred cred;
    socklen_t size = sizeof(cred);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &size) ||
            cred.uid != (uid_t)uid) { fputs("Peer UID mismatch\n", stderr); goto cleanup; }
    close(listener); listener = -1;
    if (if_nametoindex(IFACE) || !policy_free()) {
        fputs("Root TUN or reserved route table/priorities already in use; refusing to overwrite\n", stderr);
        goto cleanup;
    }
    tun = open("/dev/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) { perror("open TUN"); goto cleanup; }
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", IFACE);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    if (ioctl(tun, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); goto cleanup; }

    /* IPv4-only experiment: do not change IPv6 on any other interface. */
    int v6 = open("/proc/sys/net/ipv6/conf/" IFACE "/disable_ipv6", O_WRONLY | O_CLOEXEC);
    if (v6 >= 0) { if (write(v6, "1", 1) != 1) perror("TUN IPv6 setting"); close(v6); }
    if (command(IP " -4 addr add %s/%ld dev " IFACE, addr, prefix) ||
            command(IP " link set dev " IFACE " mtu %ld up", mtu)) goto cleanup;

    /* Limit incoming traffic and do not allow tethering through this tunnel. */
    if (command(IPT " -w 3 -I INPUT 1 -i " IFACE " -m conntrack ! --ctstate ESTABLISHED,RELATED -m comment --comment " COMMENT " -j DROP")) goto cleanup;
    input = 1;
    if (command(IPT " -w 3 -I FORWARD 1 -i " IFACE " -m comment --comment " COMMENT " -j DROP")) goto cleanup;
    forward_in = 1;
    if (command(IPT " -w 3 -I FORWARD 1 -o " IFACE " -m comment --comment " COMMENT " -j DROP")) goto cleanup;
    forward_out = 1;
    if (command(IPT " -w 3 -t nat -I POSTROUTING 1 -o " IFACE " -d %s/32 -p udp -m multiport --dports 500,4500 -m comment --comment " COMMENT " -j SNAT --to-source %s", target, addr)) goto cleanup;
    snat = 1;
    if (command(IP " -4 route add table " TABLE " %s/32 dev " IFACE " src %s", target, addr)) goto cleanup;
    route = 1;
    if (command(IP " -4 rule add pref 9100 iif lo to %s/32 ipproto udp dport 500 lookup " TABLE, target)) goto cleanup;
    rule500 = 1;
    if (command(IP " -4 rule add pref 9101 iif lo to %s/32 ipproto udp dport 4500 lookup " TABLE, target)) goto cleanup;
    rule4500 = 1;

    if (stopped || send_fd(client, tun)) { perror("send TUN fd"); goto cleanup; }
    fprintf(stderr, "Root ePDG ready: %s UDP 500/4500 via " IFACE "\n", target);
    p.fd = client; p.events = POLLIN | POLLHUP | POLLERR;
    while (!stopped) {
        int r = poll(&p, 1, 1000);
        if (r > 0) break; /* Any message, EOF or error ends this session. */
        if (r < 0 && errno != EINTR) break;
    }
    result = 0;
cleanup:
    if (rule4500) command(IP " -4 rule del pref 9101 iif lo to %s/32 ipproto udp dport 4500 lookup " TABLE, target);
    if (rule500) command(IP " -4 rule del pref 9100 iif lo to %s/32 ipproto udp dport 500 lookup " TABLE, target);
    if (route) command(IP " -4 route del table " TABLE " %s/32 dev " IFACE " src %s", target, addr);
    if (snat) command(IPT " -w 3 -t nat -D POSTROUTING -o " IFACE " -d %s/32 -p udp -m multiport --dports 500,4500 -m comment --comment " COMMENT " -j SNAT --to-source %s", target, addr);
    if (forward_out) command(IPT " -w 3 -D FORWARD -o " IFACE " -m comment --comment " COMMENT " -j DROP");
    if (forward_in) command(IPT " -w 3 -D FORWARD -i " IFACE " -m comment --comment " COMMENT " -j DROP");
    if (input) command(IPT " -w 3 -D INPUT -i " IFACE " -m conntrack ! --ctstate ESTABLISHED,RELATED -m comment --comment " COMMENT " -j DROP");
    if (tun >= 0) close(tun); /* Nonpersistent TUN disappears when all FDs close. */
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    fprintf(stderr, "Root ePDG helper exited (%d)\n", result);
    return result;
}
