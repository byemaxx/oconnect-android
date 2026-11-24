/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Privileged TUN broker. No credentials or VPN protocol processing here.
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

#define MAX_TARGETS 8
#define IP "/system/bin/ip"
#define IPT "/system/bin/iptables"
#define PREF "10500"

static volatile sig_atomic_t stopped;
static void stop_signal(int sig) { (void)sig; stopped = 1; }

/* Execute a fixed binary with separate arguments, never a shell string. */
static int command(const char *path, ...) {
    char *argv[40];
    int n = 0;
    va_list ap;
    argv[n++] = (char *)path;
    va_start(ap, path);
    while (n < 39 && (argv[n] = va_arg(ap, char *)) != NULL) n++;
    va_end(ap);
    argv[n] = NULL;
    pid_t pid = fork();
    if (pid == 0) {
        execv(path, argv);
        _exit(127);
    }
    if (pid < 0) return -1;
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "command failed:");
        for (int i = 0; i < n; i++) fprintf(stderr, " %s", argv[i]);
        fprintf(stderr, "\n");
        return -1;
    }
    return 0;
}

static int rule(const char *action, const char *target,
                const char *port, const char *table) {
    return command(IP, "-4", "rule", action, "pref", PREF, "iif", "lo",
                   "to", target, "ipproto", "udp", "dport", port,
                   "lookup", table, (char *)NULL);
}

static int nat(const char *action, const char *dev, const char *target,
               const char *port, const char *address) {
    return command(IPT, "-w", "5", "-t", "nat", action, "POSTROUTING",
                   "-o", dev, "-d", target, "-p", "udp", "--dport", port,
                   "-j", "SNAT", "--to-source", address, (char *)NULL);
}

static int send_tun(int sock, int tun) {
    char byte = 1;
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ancillary.buf;
    msg.msg_controllen = sizeof(ancillary.buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &tun, sizeof(tun));
    return sendmsg(sock, &msg, MSG_NOSIGNAL) == 1 ? 0 : -1;
}

static int number(const char *s, long min, long max, long *out) {
    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (errno || end == s || *end || n < min || n > max) return -1;
    *out = n;
    return 0;
}

static int missing_tun_error(int error) {
    return error == ENOENT || error == ENODEV || error == ENXIO;
}

/* Both names are used on Android. Preserve a real permission or device
 * error rather than masking it with ENOENT from the second path. */
static int open_tun(void) {
    int fd = open("/dev/tun", O_RDWR | O_CLOEXEC);
    if (fd >= 0) return fd;
    int first_error = errno;
    fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0 && !missing_tun_error(first_error)) errno = first_error;
    return fd;
}

/* A registered misc device proves the kernel driver is present, whether
 * built in (CONFIG_TUN=y) or supplied by an already loaded module.
 * Return -1 when the registration state cannot be determined. */
static int tun_registered(void) {
    FILE *file = fopen("/proc/misc", "r");
    if (!file) return -1;
    char line[256], name[128];
    int minor, found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%d %127s", &minor, name) == 2
                && minor == 200 && strcmp(name, "tun") == 0) {
            found = 1;
            break;
        }
    }
    if (ferror(file)) found = -1;
    fclose(file);
    return found;
}

/* Check the same privileged TUN operation used by the connection.
 * No addresses, routes, NAT rules or persistent interface are installed.
 */
static int probe(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "su did not grant UID 0\n");
        return 10;
    }
    int tun = open_tun();
    if (tun < 0) {
        int error = errno;
        fprintf(stderr, "UID 0 granted, but cannot open /dev/tun or /dev/net/tun: %s\n",
                strerror(error));
        if (!missing_tun_error(error)) return 13;
        int registered = tun_registered();
        if (registered == 1) {
            fprintf(stderr, "TUN driver already registered; check device nodes and SELinux. Module loading skipped.\n");
            return 14;
        }
        if (registered < 0) {
            fprintf(stderr, "Cannot verify /proc/misc; module loading skipped.\n");
            return 15;
        }
        return 11;
    }
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "acprobe%%d");
    if (ioctl(tun, TUNSETIFF, &ifr)) {
        perror("UID 0 granted, but TUNSETIFF failed");
        close(tun);
        return 12;
    }
    close(tun);
    puts("ROOT_TUN_PROBE_OK");
    return 0;
}

/* Prefer the running kernel's TUN driver. Only use an existing OS-provided
 * module if the device is unavailable, never a bundled foreign kernel module.
 */
static int ensure_tun(void) {
    int status = probe();
    if (status == 0) {
        puts("TUN already available; module loading skipped");
        return 0;
    }
    if (status != 11) return status;
    const char *paths[] = {
        "/system/lib/modules/tun.ko",
        "/vendor/lib/modules/tun.ko",
        "/vendor_dlkm/lib/modules/tun.ko",
        "/system_dlkm/lib/modules/tun.ko",
        "/odm/lib/modules/tun.ko",
        "/odm_dlkm/lib/modules/tun.ko"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], R_OK) != 0) continue;
        /* The kernel enforces module ABI, signature and loading restrictions. */
        if (command("/system/bin/insmod", paths[i], (char *)NULL) == 0) {
            puts("Loaded device-provided TUN module");
            return probe();
        }
        /* A concurrent loader may already have made TUN available. */
        status = probe();
        if (status != 11) return status;
    }
    fprintf(stderr, "TUN unavailable; no compatible device-provided module could be loaded\n");
    return 11;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) return probe();
    if (argc == 2 && strcmp(argv[1], "--ensure-tun") == 0) return ensure_tun();
    if (geteuid() != 0) {
        fprintf(stderr, "su did not grant UID 0\n");
        return 10;
    }
    if (argc < 6 || argc > 5 + MAX_TARGETS) return 2;
    const char *name = argv[1];
    const char *prefix = "oconnect-root-";
    size_t prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) ||
        strlen(name) != prefix_len + 32 ||
        strspn(name + prefix_len, "0123456789abcdef") != 32) return 2;
    long uid, mtu, bits;
    if (number(argv[2], 10000, 2147483647L, &uid) ||
        number(argv[4], 576, 9000, &mtu)) return 2;
    char address[INET_ADDRSTRLEN], cidr[32], targets[MAX_TARGETS][32];
    const char *slash = strchr(argv[3], '/');
    struct in_addr tmp;
    if (!slash || slash - argv[3] >= (long)sizeof(address) || slash == argv[3])
        return 2;
    memcpy(address, argv[3], (size_t)(slash - argv[3]));
    address[slash - argv[3]] = 0;
    if (inet_pton(AF_INET, address, &tmp) != 1 ||
        number(slash + 1, 0, 32, &bits)) return 2;
    snprintf(cidr, sizeof(cidr), "%s/%ld", address, bits);
    int count = argc - 5;
    for (int i = 0; i < count; i++) {
        if (inet_pton(AF_INET, argv[i + 5], &tmp) != 1) return 2;
        snprintf(targets[i], sizeof(targets[i]), "%s/32", argv[i + 5]);
    }
    char table[16], dev[IFNAMSIZ];
    /* A session-specific table/name. Never flush other routing tables. */
    char hex[7] = {0};
    memcpy(hex, name + prefix_len, 6);
    unsigned long token = strtoul(hex, NULL, 16);
    snprintf(table, sizeof(table), "%lu", 100000UL + token);
    snprintf(dev, sizeof(dev), "acv%s", hex);
    if (if_nametoindex(dev)) return 2;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop_signal);
    signal(SIGINT, stop_signal);
    signal(SIGHUP, stop_signal);
    int listener = -1, client = -1, tun = -1, route_added = 0, rc = 1;
    int rules[MAX_TARGETS][2] = {{0}}, nats[MAX_TARGETS][2] = {{0}};
    const char *ports[] = {"500", "4500"};
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, name, strlen(name));
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 ||
        bind(listener, (struct sockaddr *)&addr,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name))) ||
        listen(listener, 1)) {
        perror("root control socket");
        goto done;
    }
    struct pollfd p = {.fd = listener, .events = POLLIN};
    if (poll(&p, 1, 20000) != 1 || stopped) goto done;
    client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) goto done;
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) ||
        peer.uid != (uid_t)uid) {
        fprintf(stderr, "unexpected control peer UID\n");
        goto done;
    }
    close(listener);
    listener = -1;

    tun = open_tun();
    if (tun < 0) { perror("open TUN"); goto done; }
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
    if (ioctl(tun, TUNSETIFF, &ifr)) { perror("TUNSETIFF"); goto done; }

    if (command(IP, "-4", "addr", "add", cidr, "dev", dev, (char *)NULL) ||
        command(IP, "link", "set", "dev", dev, "mtu", argv[4], "up", (char *)NULL) ||
        command(IP, "-4", "route", "add", "default", "dev", dev, "src", address,
                "table", table, (char *)NULL)) goto done;
    route_added = 1;

    for (int i = 0; i < count; i++) {
        for (int j = 0; j < 2; j++) {
            if (stopped || nat("-A", dev, targets[i], ports[j], address)) goto done;
            nats[i][j] = 1;
            if (rule("add", targets[i], ports[j], table)) goto done;
            rules[i][j] = 1;
        }
    }
    if (stopped || send_tun(client, tun)) goto done;
    fprintf(stderr, "Root TUN ready: %s, table %s, IPv4 targets %d\n", dev, table, count);

    /* EOF or peer death triggers cleanup. The TUN is never made persistent. */
    p.fd = client;
    p.events = POLLIN | POLLHUP | POLLERR;
    while (!stopped) {
        int ready = poll(&p, 1, 1000);
        if (ready < 0 && errno != EINTR) break;
        if (ready > 0) break;
    }
    rc = 0;
done:
    for (int i = count - 1; i >= 0; i--) {
        for (int j = 1; j >= 0; j--) {
            if (rules[i][j]) rule("del", targets[i], ports[j], table);
            if (nats[i][j]) nat("-D", dev, targets[i], ports[j], address);
        }
    }
    if (route_added) command(IP, "-4", "route", "del", "default", "dev", dev,
                             "src", address, "table", table, (char *)NULL);
    if (tun >= 0) close(tun);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    fprintf(stderr, "Root TUN stopped: %s, result %d\n", dev, rc);
    return rc;
}
