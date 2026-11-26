/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ROOT_RELAY_H
#define ROOT_RELAY_H

#include <net/if.h>
#include <stdatomic.h>
#include <sys/types.h>

#define EPDG_MAX_MODEM_INTERFACES 16

struct epdg_flow {
    atomic_uint modem_ifindex;
    unsigned modem_interfaces[EPDG_MAX_MODEM_INTERFACES];
    unsigned modem_count;
};

struct epdg_relay {
    const char *wifi, *endpoint, *vpn, *table, *tunnel, *hostname;
    char dummy[IFNAMSIZ];
    struct epdg_flow *flow;
    pid_t workers[3];
    int dummy_created, route_added, outbound500, outbound4500;
};

int root_command(const char *path, ...);
int epdg_dns_worker(int ready, int argc, char **argv, struct epdg_flow *flow);
int epdg_ike_worker(int ready, int argc, char **argv, struct epdg_flow *flow);

int epdg_relay_probe(const char *wifi);
int epdg_relay_start(struct epdg_relay *relay, const char *wifi_ip, const char *dns4,
                     const char *dns6, int tun, int control);
int epdg_relay_alive(const struct epdg_relay *relay);
void epdg_relay_stop(struct epdg_relay *relay);

#endif
