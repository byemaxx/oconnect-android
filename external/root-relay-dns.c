#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned read16(const unsigned char *p) {
    return (unsigned)p[0] * 256 + p[1];
}

static void write16(unsigned char *p, unsigned value) {
    p[0] = value >> 8;
    p[1] = value;
}

int epdg_dns_worker(int ready, int argc, char **argv) {
    if (argc != 6) return 2;
    struct in_addr old_ip, old_dns;
    struct in6_addr router6;
    int ipv6 = strchr(argv[3], ':') != NULL;
    struct sockaddr_in resolver = {.sin_family = AF_INET, .sin_port = htons(53)};
    struct sockaddr_ll reverse = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)if_nametoindex(argv[1])
    };
    if (!reverse.sll_ifindex ||
        (ipv6 ? inet_pton(AF_INET6, argv[3], &router6) != 1 :
         inet_pton(AF_INET, argv[2], &old_ip) != 1 || inet_pton(AF_INET, argv[3], &old_dns) != 1) ||
        inet_pton(AF_INET, argv[5], &resolver.sin_addr) != 1) return 2;

    int packets = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (packets < 0 || bind(packets, (struct sockaddr *)&reverse, sizeof(reverse)) < 0) {
        perror("packet relay setup");
        return 1;
    }
    reverse.sll_protocol = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP);
    if (write(ready, "1", 1) != 1) return 1;
    close(ready);
    static const char name[] = "\4epdg\3epc\6mnc490\6mcc302\3pub\13" "3gppnetwork\3org";
    unsigned char query[2048];
    unsigned char response[1500];
    for (;;) {
        struct sockaddr_ll origin;
        socklen_t origin_len = sizeof(origin);
        ssize_t len = recvfrom(packets, query, sizeof(query), 0,
                               (struct sockaddr *)&origin, &origin_len);
        if (len < 0) {
            if (errno == ENETDOWN || errno == EINTR) {
                usleep(100000);
                continue;
            }
            perror("receive packet");
            return 1;
        }
        unsigned header = ipv6 ? 40 : 20;
        unsigned dns_offset = header + 8;
        if ((unsigned)len < dns_offset || origin.sll_pkttype == PACKET_OUTGOING) continue;
        if (ipv6) {
            if ((query[0] >> 4) != 6 || query[6] != IPPROTO_UDP ||
                query[8] != 0xfe || (query[9] & 0xc0) != 0x80 ||
                memcmp(query + 24, &router6, 16)) continue;
        } else if (query[0] != 0x45 || (read16(query + 6) & 0x3fff) ||
                   query[9] != IPPROTO_UDP || memcmp(query + 12, &old_ip, 4) ||
                   memcmp(query + 16, &old_dns, 4)) continue;
        const unsigned char *request = query + dns_offset;
        unsigned udp_len = read16(query + header + 4);
        if (read16(query + header + 2) != 53 || udp_len < 8 + 12 + sizeof(name) + 4 ||
            udp_len + header > (unsigned)len ||
            udp_len != (ipv6 ? read16(query + 4) : read16(query + 2) - 20) ||
            (request[2] & 0x80) || memcmp(request + 12, name, sizeof(name))) continue;

        unsigned char *dns = response + dns_offset;
        const unsigned char *question_type = request + 12 + sizeof(name);
        unsigned type = read16(question_type);
        if (read16(request + 4) != 1 || read16(question_type + 2) != 1 ||
            (type != 1 && type != 28)) continue;
        ssize_t bytes = 12 + sizeof(name) + 4;
        memcpy(dns, request, (size_t)bytes);
        dns[2] = 0x80 | (dns[2] & 1);
        dns[3] = 0x80;
        memset(dns + 6, 0, 6);
        if (type == 1) {
            static const unsigned char record[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 15, 0, 4};
            write16(dns + 6, 1);
            memcpy(dns + bytes, record, sizeof(record));
            memcpy(dns + bytes + sizeof(record), &resolver.sin_addr, 4);
            bytes += sizeof(record) + 4;
        }

        unsigned total = dns_offset + (unsigned)bytes;
        memset(response, 0, dns_offset);
        unsigned char *udp = response + header;
        write16(udp, 53);
        write16(udp + 2, read16(query + header));
        write16(udp + 4, bytes + 8);
        if (ipv6) {
            response[0] = 0x60;
            write16(response + 4, bytes + 8);
            response[6] = IPPROTO_UDP;
            response[7] = 64;
            memcpy(response + 8, &router6, 16);
            memcpy(response + 24, query + 8, 16);
            unsigned sum = IPPROTO_UDP + (unsigned)bytes + 8;
            for (unsigned i = 8; i + 1 < total; i += 2) sum += read16(response + i);
            if (total & 1) sum += (unsigned)response[total - 1] << 8;
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            write16(udp + 6, sum == 0xffff ? 0xffff : ~sum);
        } else {
            response[0] = 0x45;
            write16(response + 2, total);
            response[8] = 64;
            response[9] = IPPROTO_UDP;
            memcpy(response + 12, &old_dns, 4);
            memcpy(response + 16, &old_ip, 4);
            unsigned sum = 0;
            for (int i = 0; i < 20; i += 2) sum += read16(response + i);
            write16(response + 10, ~((sum & 0xffff) + (sum >> 16)));
        }
        if (sendto(packets, response, total, 0,
                   (struct sockaddr *)&reverse, sizeof(reverse)) != (ssize_t)total) {
            perror("send response to modem");
            continue;
        }
    }
}
/* SPDX-License-Identifier: GPL-2.0-or-later */
