/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "root-relay.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define IP "/system/bin/ip"
#define TC "/system/bin/tc"
#define PREF "19421"

static int start_worker(pid_t *worker, int (*run)(int, int, char **),
                        int argc, char **argv, int tun, int control) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) return -1;
    const pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == 0) {
        close(ready[0]);
        close(tun);
        close(control);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(1);
        _exit(run(ready[1], argc, argv));
    }
    close(ready[1]);
    if (pid < 0) {
        close(ready[0]);
        return -1;
    }
    *worker = pid;
    struct pollfd status = {.fd = ready[0], .events = POLLIN};
    char result;
    int ok = poll(&status, 1, 3000) == 1 && read(ready[0], &result, 1) == 1
            && result == '1';
    close(ready[0]);
    return ok ? 0 : -1;
}

static int find_modem(char modem[IFNAMSIZ]) {
    const char prefix[] = "r_rmnet_data";
    struct if_nameindex *interfaces = if_nameindex();
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int count = 0;
    if (interfaces && fd >= 0) {
        for (struct if_nameindex *it = interfaces; it->if_index; ++it) {
            if (strncmp(it->if_name, prefix, sizeof(prefix) - 1) != 0) continue;
            struct ifreq request = {0};
            snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", it->if_name);
            if (ioctl(fd, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP)) {
                snprintf(modem, IFNAMSIZ, "%s", request.ifr_name);
                count++;
            }
        }
    }
    if (interfaces) if_freenameindex(interfaces);
    if (fd >= 0) close(fd);
    if (count == 1) return 0;
    fprintf(stderr, "Freedom relay needs one active Qualcomm reverse rmnet interface (found %d)\n", count);
    return -1;
}

static int route(const struct epdg_relay *r, const char *action) {
    return root_command(IP, "-4", "rule", action, "pref", "10493", "iif", "lo",
                        "uidrange", "0-0", "from", r->vpn, "to", r->endpoint,
                        "lookup", r->table, (char *)NULL);
}

static int outbound(const struct epdg_relay *r, const char *wifi_ip,
                    const char *port, const char *handle) {
    return root_command(TC, "filter", "add", "dev", r->wifi, "egress", "protocol", "ip",
            "pref", PREF, "handle", handle, "u32", "match", "ip", "src", wifi_ip,
            "match", "ip", "dst", r->endpoint, "match", "ip", "protocol", "17", "0xff",
            "match", "ip", "dport", port, "0xffff", "action", "mirred", "egress",
            "redirect", "dev", r->dummy, (char *)NULL);
}

int epdg_relay_start(struct epdg_relay *r, const char *wifi_ip, const char *dns4,
                     const char *dns6, int tun, int control) {
    struct in_addr ip4;
    struct in6_addr ip6;
    char modem[IFNAMSIZ];
    int v4 = strcmp(dns4, "-") != 0;
    int v6 = strcmp(dns6, "-") != 0;
    if ((!v4 && !v6) || !if_nametoindex(r->wifi) ||
        inet_pton(AF_INET, wifi_ip, &ip4) != 1 ||
        (v4 && inet_pton(AF_INET, dns4, &ip4) != 1) ||
        (v6 && (inet_pton(AF_INET6, dns6, &ip6) != 1 || !IN6_IS_ADDR_LINKLOCAL(&ip6))) ||
        find_modem(modem)) return -1;

    char wifi_cidr[INET_ADDRSTRLEN + 3], endpoint_cidr[INET_ADDRSTRLEN + 3];
    snprintf(wifi_cidr, sizeof(wifi_cidr), "%s/32", wifi_ip);
    snprintf(endpoint_cidr, sizeof(endpoint_cidr), "%s/32", r->endpoint);
    if (root_command(IP, "link", "add", r->dummy, "type", "dummy", (char *)NULL)) return -1;
    r->dummy_created = 1;
    if (root_command(IP, "link", "set", r->dummy, "up", (char *)NULL) ||
        root_command(TC, "qdisc", "add", "dev", r->dummy, "clsact", (char *)NULL) ||
        root_command(TC, "filter", "add", "dev", r->dummy, "egress", "protocol", "ip",
            "pref", PREF, "u32", "match", "ip", "src", endpoint_cidr,
            "match", "ip", "dst", wifi_cidr, "match", "ip", "protocol", "17", "0xff",
            "match", "ip", "sport", "4500", "0xffff", "action", "mirred", "ingress",
            "redirect", "dev", r->wifi, (char *)NULL) ||
        route(r, "add")) return -1;
    r->route_added = 1;
    char *ike[] = {NULL, modem, (char *)wifi_ip, (char *)r->vpn, (char *)r->endpoint,
                   (char *)r->tunnel, r->dummy, NULL};
    char *dns[] = {NULL, modem, (char *)wifi_ip, (char *)dns4, "--fixed-a",
                   (char *)r->endpoint, NULL};
    if (start_worker(&r->workers[0], epdg_ike_worker, 7, ike, tun, control) ||
        (v4 && start_worker(&r->workers[1], epdg_dns_worker, 6, dns, tun, control))) return -1;
    dns[3] = (char *)dns6;
    if (v6 && start_worker(&r->workers[2], epdg_dns_worker, 6, dns, tun, control)) return -1;

    if (outbound(r, wifi_cidr, "500", "800::811")) return -1;
    r->outbound500 = 1;
    if (outbound(r, wifi_cidr, "4500", "800::812")) return -1;
    r->outbound4500 = 1;
    fprintf(stderr, "Freedom relay ready: %s via %s (IKE and ESP)\n", modem, r->tunnel);
    return 0;
}

int epdg_relay_alive(const struct epdg_relay *r) {
    for (size_t i = 0; i < 3; ++i) {
        if (!r->workers[i]) continue;
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)r->workers[i], &info, WEXITED | WNOHANG | WNOWAIT) == 0
                && info.si_pid) return 0;
    }
    return 1;
}

void epdg_relay_stop(struct epdg_relay *r) {
    if (r->outbound4500 || r->outbound500) {
        const char *handles[] = {r->outbound4500 ? "800::812" : NULL,
                                 r->outbound500 ? "800::811" : NULL};
        for (size_t i = 0; i < 2; ++i) {
            if (handles[i]) root_command(TC, "filter", "del", "dev", r->wifi, "egress",
                    "protocol", "ip", "pref", PREF, "handle", handles[i], "u32", (char *)NULL);
        }
    }
    for (size_t i = 0; i < 3; ++i) {
        if (!r->workers[i]) continue;
        kill(r->workers[i], SIGTERM);
        while (waitpid(r->workers[i], NULL, 0) < 0 && errno == EINTR) {}
    }
    if (r->route_added) route(r, "del");
    if (r->dummy_created) root_command(IP, "link", "del", r->dummy, (char *)NULL);
}
