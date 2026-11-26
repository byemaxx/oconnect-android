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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define IP "/system/bin/ip"
#define TC "/system/bin/tc"
#define PREF "19421"

static int start_worker(pid_t *worker, int (*run)(int, int, char **, struct epdg_flow *),
                        int argc, char **argv, int tun, int control, struct epdg_flow *flow) {
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
        _exit(run(ready[1], argc, argv, flow));
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

static int find_modem(struct epdg_flow *flow) {
    const char prefix[] = "r_rmnet_data";
    struct if_nameindex *interfaces = if_nameindex();
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    unsigned active_count = 0, active = 0;
    if (interfaces && fd >= 0) {
        for (struct if_nameindex *it = interfaces; it->if_index; ++it) {
            if (strncmp(it->if_name, prefix, sizeof(prefix) - 1) != 0) continue;
            if (flow->modem_count == EPDG_MAX_MODEM_INTERFACES) break;
            flow->modem_interfaces[flow->modem_count++] = it->if_index;
            struct ifreq request = {0};
            snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", it->if_name);
            if (ioctl(fd, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP)) {
                active = it->if_index;
                active_count++;
            }
        }
    }
    if (interfaces) if_freenameindex(interfaces);
    if (fd >= 0) close(fd);
    atomic_init(&flow->modem_ifindex, active_count == 1 ? active : 0);
    if (flow->modem_count) return 0;
    fprintf(stderr, "Freedom relay found no Qualcomm reverse rmnet interface\n");
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

int epdg_relay_probe(const char *wifi) {
    if (!if_nametoindex(wifi) || access(TC, X_OK)) {
        fprintf(stderr, "Freedom relay requires Android traffic control and an active Wi-Fi interface\n");
        return 1;
    }
    struct if_nameindex *interfaces = if_nameindex();
    int supported = 0;
    if (interfaces) {
        for (struct if_nameindex *it = interfaces; it->if_index; ++it) {
            if (strncmp(it->if_name, "r_rmnet_data", sizeof("r_rmnet_data") - 1) == 0) {
                supported = 1;
                break;
            }
        }
        if_freenameindex(interfaces);
    }
    if (!supported) {
        fprintf(stderr, "Freedom relay requires Qualcomm reverse rmnet\n");
        return 1;
    }
    puts("FREEDOM_PROBE_OK");
    return 0;
}

int epdg_relay_start(struct epdg_relay *r, const char *wifi_ip, const char *dns4,
                     const char *dns6, int tun, int control) {
    struct in_addr ip4;
    int v4 = strcmp(dns4, "-") != 0;
    int v6 = strcmp(dns6, "-") != 0;
    if ((!v4 && !v6) || !if_nametoindex(r->wifi) ||
        inet_pton(AF_INET, wifi_ip, &ip4) != 1) return -1;
    void *shared = mmap(NULL, sizeof(*r->flow), PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return -1;
    r->flow = shared;
    if (find_modem(r->flow)) return -1;

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
    char *ike[] = {(char *)wifi_ip, (char *)r->vpn, (char *)r->endpoint,
                   (char *)r->tunnel, r->dummy};
    char *dns[] = {(char *)wifi_ip, (char *)dns4, (char *)r->endpoint};
    if (start_worker(&r->workers[0], epdg_ike_worker, 5, ike, tun, control, r->flow) ||
        (v4 && start_worker(&r->workers[1], epdg_dns_worker, 3, dns, tun, control, r->flow))) return -1;
    dns[1] = (char *)dns6;
    if (v6 && start_worker(&r->workers[2], epdg_dns_worker, 3, dns, tun, control, r->flow)) return -1;

    if (outbound(r, wifi_cidr, "500", "800::811")) return -1;
    r->outbound500 = 1;
    if (outbound(r, wifi_cidr, "4500", "800::812")) return -1;
    r->outbound4500 = 1;
    fprintf(stderr, "Freedom relay ready via %s (IKE and ESP)\n", r->tunnel);
    return 0;
}

int epdg_relay_alive(const struct epdg_relay *r) {
    if (!if_nametoindex(r->wifi)) return 0;
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
    if (r->flow) munmap(r->flow, sizeof(*r->flow));
    if (r->route_added) route(r, "del");
    if (r->dummy_created) root_command(IP, "link", "del", r->dummy, (char *)NULL);
}
