#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "root-relay.h"

static unsigned word(const unsigned char *p) {
    return (unsigned)p[0] * 256 + p[1];
}

static void write_word(unsigned char *p, unsigned n) {
    p[0] = n >> 8;
    p[1] = n;
}

int epdg_ike_worker(int ready, int argc, char **argv, struct epdg_flow *flow) {
    if (argc != 5 || strlen(argv[3]) >= IFNAMSIZ) return 2;
    struct sockaddr_in local = {.sin_family = AF_INET};
    struct in_addr modem, endpoint;
    if (inet_pton(AF_INET, argv[0], &modem) != 1 ||
        inet_pton(AF_INET, argv[1], &local.sin_addr) != 1 ||
        inet_pton(AF_INET, argv[2], &endpoint) != 1) return 2;
    struct sockaddr_ll device = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL)};
    int raw = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_ll capture = device;
    capture.sll_ifindex = (int)if_nametoindex(argv[4]);
    if (!capture.sll_ifindex || raw < 0 || udp < 0 ||
        bind(raw, (struct sockaddr *)&capture, sizeof(capture)) < 0 ||
        setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE, argv[3], strlen(argv[3]) + 1) < 0 ||
        bind(udp, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("relay setup");
        return 1;
    }
    if (write(ready, "1", 1) != 1) return 1;
    close(ready);
    device.sll_protocol = htons(ETH_P_IP);
    capture.sll_protocol = htons(ETH_P_IP);
    capture.sll_halen = ETH_ALEN;
    struct pollfd fds[] = {{raw, POLLIN, 0}, {udp, POLLIN, 0}};
    unsigned modem_port[2] = {0};
    const unsigned char marker[4] = {0};
    int reported_ike = 0, received_esp = 0, sent_esp = 0, reported_esp = 0;
    unsigned char data[65536];
    while (poll(fds, 2, -1) > 0) {
        if (fds[0].revents & (POLLIN | POLLERR)) {
            struct sockaddr_ll sender;
            socklen_t size = sizeof(sender);
            ssize_t n = recvfrom(raw, data, sizeof(data), 0, (struct sockaddr *)&sender, &size);
            if (n < 0) usleep(100000);
            if (n >= 28 && sender.sll_pkttype == PACKET_OUTGOING && data[0] == 0x45 &&
                data[9] == IPPROTO_UDP && !(word(data + 6) & 0x3fff) &&
                !memcmp(data + 12, &modem, 4) && !memcmp(data + 16, &endpoint, 4)) {
                unsigned port = word(data + 22), length = word(data + 24);
                if ((port == 500 || port == 4500) && length >= 8 &&
                    length == word(data + 2) - 20 && length <= (unsigned)n - 20) {
                    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(port),
                                               .sin_addr = endpoint};
                    modem_port[port == 4500] = word(data + 20);
                    if (sendto(udp, data + 28, length - 8, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                        perror("VPN send");
                    } else if (port == 4500 && length >= 16 &&
                               memcmp(data + 28, marker, sizeof(marker))) {
                        sent_esp = 1;
                    }
                }
            }
        }
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in sender;
            socklen_t size = sizeof(sender);
            ssize_t n = recvfrom(udp, data + 28, sizeof(data) - 28, 0,
                                 (struct sockaddr *)&sender, &size);
            unsigned port = n >= 0 ? ntohs(sender.sin_port) : 0;
            if (n < 0 || sender.sin_addr.s_addr != endpoint.s_addr ||
                (port != 500 && port != 4500) || !modem_port[port == 4500]) continue;
            int esp = port == 4500 && n >= 8 && memcmp(data + 28, marker, sizeof(marker));
            memset(data, 0, 28);
            data[0] = 0x45;
            write_word(data + 2, n + 28);
            data[8] = 64;
            data[9] = IPPROTO_UDP;
            memcpy(data + 12, &endpoint, 4);
            memcpy(data + 16, &modem, 4);
            unsigned sum = 0;
            for (unsigned i = 0; i < 20; i += 2) sum += word(data + i);
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            write_word(data + 10, ~sum);
            write_word(data + 20, port);
            write_word(data + 22, modem_port[port == 4500]);
            write_word(data + 24, n + 8);
            device.sll_ifindex = (int)atomic_load(&flow->modem_ifindex);
            if (!esp && device.sll_ifindex == 0) continue;
            struct sockaddr_ll *recipient = esp ? &capture : &device;
            ssize_t sent = sendto(raw, data, n + 28, 0, (struct sockaddr *)recipient,
                                  sizeof(*recipient));
            if (sent < 0) {
                perror(esp ? "kernel ESP send" : "modem send");
            } else if (esp) {
                received_esp = 1;
            } else if (n >= 28 && !reported_ike) {
                fprintf(stderr, "Freedom-stage ike\n");
                reported_ike = 1;
            }
        }
        if (sent_esp && received_esp && !reported_esp) {
            fprintf(stderr, "Freedom-stage esp\n");
            reported_esp = 1;
        }
    }
    return 1;
}
/* SPDX-License-Identifier: GPL-2.0-or-later */
