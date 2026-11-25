/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ROOT_RELAY_H
#define ROOT_RELAY_H

#include <net/if.h>
#include <sys/types.h>

struct epdg_relay {
    const char *wifi, *endpoint, *vpn, *table, *tunnel;
    char dummy[IFNAMSIZ];
    pid_t workers[3];
    int dummy_created, route_added, outbound500, outbound4500;
};

int root_command(const char *path, ...);
int epdg_dns_worker(int ready, int argc, char **argv);
int epdg_ike_worker(int ready, int argc, char **argv);

int epdg_relay_start(struct epdg_relay *relay, const char *wifi_ip, const char *dns4,
                     const char *dns6, int tun, int control);
int epdg_relay_alive(const struct epdg_relay *relay);
void epdg_relay_stop(struct epdg_relay *relay);

#endif
