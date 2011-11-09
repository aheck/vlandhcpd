/*
 * Copyright (c) 2011 Andreas Heck <aheck@gmx.de>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <errno.h>
#include <pcap.h>
#include <glib.h>

#include "dhcp.h"

const char *msgtypes[9] = {
    "UNKNOWN",
    "DHCPDISCOVER",
    "DHCPOFFER",
    "DHCPREQUEST",
    "DHCPDECLINE",
    "DHCPACK",
    "DHCPNAK",
    "DHCPRELEASE",
    "DHCPINFORM"
};

struct client_conf* lookup_client(struct server_conf *conf, int vlan,
        unsigned char mac[ETH_ALEN]) {
    struct group_config *group;

    group = g_hash_table_lookup(conf->group_by_vlan, &vlan);
    if (group == NULL) return NULL;

    return g_hash_table_lookup(group->client_by_mac, mac);
}

void init_packet(struct pktbuf *pkt, struct pktbuf *inpkt, struct client_conf *client) {
    int i;
    unsigned char *srcmac = inpkt->eth_header->h_source;

    memset(pkt, 0, sizeof(struct pktbuf));

    g_strlcpy(pkt->iface, inpkt->iface, PKT_IFACE_MAX_LEN);
    pkt->vlan = inpkt->vlan;
    pkt->tagged = inpkt->tagged;
    pkt->eth_header = (struct ethhdr *) pkt->buffer;

    for (i = 0; i < ETH_ALEN; i++) {
        pkt->eth_header->h_dest[i] = 255;
        pkt->eth_header->h_source[i] = srcmac[i];
    }

    pktbuf_init_layer2(pkt, inpkt, ETH_P_IP);

    if (pkt->tagged) {
        pkt->eth_header_vlan = (struct ethhdrvlan *) pkt->buffer;
        pkt->eth_header_vlan->tpid = htons(ETH_P_8021Q);
        pkt->eth_header_vlan->tci = inpkt->eth_header_vlan->tci;
        pkt->eth_header_vlan->h_proto = htons(ETH_P_IP);
        pkt->ip_header = (struct iphdr *) (((void*) pkt->eth_header_vlan) + sizeof(struct ethhdrvlan));
    } else {
        pkt->eth_header->h_proto = htons(ETH_P_IP);
        pkt->ip_header = (struct iphdr *) (((void*) pkt->eth_header) + sizeof(struct ethhdr));
    }

    pkt->udp_header = (struct udphdr *) (((void*) pkt->ip_header) + sizeof(struct iphdr));
    pkt->dhcp_packet = (struct dhcp_pkt *) (((void*) pkt->udp_header) + sizeof(struct udphdr));

    pkt->ip_header->version = 4;
    pkt->ip_header->ihl = sizeof(struct iphdr) / 4;
    pkt->ip_header->tos = 0;
    pkt->ip_header->id = 0;
    pkt->ip_header->frag_off = 0;
    pkt->ip_header->ttl = 255;
    pkt->ip_header->protocol = IPPROTO_UDP;

    pkt->ip_header->daddr = 0xffffffff;
    pkt->ip_header->saddr = client->group->server_ip.addr;

    /*
     * Fill in the UDP header
     */

    pkt->udp_header->source = htons(DHCP_PORT_SERVER);
    pkt->udp_header->dest = htons(DHCP_PORT_CLIENT);

    /*
     * Fill in the DHCP Packet
     */

    pkt->dhcp_packet->op = 2;
    pkt->dhcp_packet->htype = 1;
    pkt->dhcp_packet->hlen = 6;
    pkt->dhcp_packet->hops = 0;

    pkt->dhcp_packet->siaddr = client->group->server_ip.addr;
    pkt->dhcp_packet->yiaddr = *((guint32 *) &client->ip);

    for (i = 0; i < ETH_ALEN; i++) {
        pkt->dhcp_packet->chaddr[i] = srcmac[i];
    }

    pkt->dhcplen = sizeof(struct dhcp_pkt) + pkt->optlen;

    pkt->ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + pkt->dhcplen);
    pkt->udp_header->len = htons(sizeof(struct udphdr) + pkt->dhcplen);

    pkt->pktlen = sizeof(struct iphdr)
        + sizeof(struct udphdr) + pkt->dhcplen;
    if (inpkt->tagged) {
        pkt->pktlen += sizeof(struct ethhdrvlan);
    } else {
        pkt->pktlen += sizeof(struct ethhdr);
    }
}

void build_options(struct pktbuf *pkt, int msgtype, struct client_conf *client) {
    int i = 0;
    int j;
    unsigned char *o;

    o = pkt->dhcp_packet->options;
    // magic number
    memcpy(o, "\x63\x82\x53\x63", 4);
    i += 4;

    // DHCP Message type
    o[i++] = 53;
    o[i++] = 1;
    o[i++] = msgtype;

    // Server Identifier
    o[i++] = 54;
    o[i++] = 4;
    memcpy(&o[i], &client->group->server_ip, 4);
    i += 4;

    // Lease
    o[i++] = 51;
    o[i++] = 4;
    *((guint32*) &o[i]) = client->group->lease;
    *((guint32*) &o[i]) = htonl(*((guint32*) &o[i]));
    i += 4;

    // Subnet Mask
    o[i++] = 1;
    o[i++] = 4;
    memcpy(&o[i], &client->group->netmask, 4);
    i += 4;

    // Router
    o[i++] = 3;
    o[i++] = 4;
    memcpy(&o[i], &client->group->router_ip, 4);
    i += 4;

    // DNS Servers
    o[i++] = 6;
    o[i++] = 0;

    for (j = 0;; j++) {
        if (client->group->dns_servers[j].addr == 0) break;

        memcpy(&o[i], &client->group->dns_servers[j].addr, 4);
        i += 4;
    }

    // set length to real value
    o[i - j*4 - 1] = j*4;

    // Terminate options
    o[i++] = 255;

    pkt->optlen = i;
    pkt->pktlen += pkt->optlen;
}

gboolean system_has_vlan_iface(gchar *iface, guint16 vlanid) {
    GString *buffer;
    gboolean result = FALSE;

    fprintf(stderr, "system_has_vlan_iface called!\n");

    buffer = g_string_new("");
    g_string_printf(buffer, "/proc/sys/net/ipv4/conf/%s.%i", iface, vlanid);
    fprintf(stderr, "checking iface: %s\n", buffer->str);

    if (g_file_test(buffer->str, G_FILE_TEST_EXISTS)
            && g_file_test(buffer->str, G_FILE_TEST_IS_DIR)) {
        result = TRUE;
    }

    g_string_free(buffer, TRUE);

    return result;
}

void send_packet(pcap_t *p, struct pktbuf *pkt) {
    fprintf(stderr, "send_packet called\n");
    pkt->ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + pkt->dhcplen + pkt->optlen);
    pkt->udp_header->len = htons(sizeof(struct udphdr) + pkt->dhcplen + pkt->optlen);

    pktbuf_csum(pkt);

    /* If we send a response for a VLAN over the trunk interface while
     * the host system has a VLAN interface for the respective VLAN a
     * client which listens on the host would not get the response
     * because it never shows up on the local VLAN interface but only
     * on the trunk interface.
     *
     * Therfore we send the response over the systems VLAN interface if
     * exists and we use the trunk interface otherwise.
    */
    if (pkt->tagged && system_has_vlan_iface(pkt->iface, pkt->vlan)) {
        fprintf(stderr, "send on vlan iface!\n");
        pktbuf_send_on_vlan_iface(p, pkt);
    } else {
        fprintf(stderr, "send on normal iface!\n");
        pktbuf_send(p, pkt);
    }
}

void send_offer(pcap_t *p, struct pktbuf *inpkt, struct client_conf *client) {
    struct pktbuf *pkt;

    pkt = malloc(sizeof(struct pktbuf));
    init_packet(pkt, inpkt, client);

    pkt->dhcp_packet->xid = inpkt->dhcp_packet->xid;
    build_options(pkt, DHCPOFFER, client);

    pktbuf_csum(pkt);

    fprintf(stderr, "\n\nWriting DHCPOFFER to aslfajssocket: %d bytes\n\n", pkt->pktlen);

    send_packet(p, pkt);

    free(pkt);
}

void send_ack(pcap_t *p, struct pktbuf *inpkt, struct client_conf *client) {
    struct pktbuf *pkt;

    pkt = malloc(sizeof(struct pktbuf));
    init_packet(pkt, inpkt, client);

    pkt->dhcp_packet->xid = inpkt->dhcp_packet->xid;
    build_options(pkt, DHCPACK, client);

    fprintf(stderr, "\n\nWriting DHCPACK to socket: %d bytes\n\n", pkt->pktlen);

    send_packet(p, pkt);

    free(pkt);
}

// check if we still have num bytes of options
#define CHKOPTLEN(num) if (inpkt->optlen < i + num) return;

void handle_dhcp(struct server_conf *conf, pcap_t *p, struct pktbuf *inpkt) {
    unsigned char tag, len;
    int i, j;
    int msgtype;
    union ip_address ip;
    unsigned char buffer[512];
    guint32 lease;
    unsigned char *options = inpkt->dhcp_packet->options;
    unsigned char *srcmac = inpkt->eth_header->h_source;
    struct client_conf *client;

#if DEBUG
    fprintf(stderr, "Optionslen: %d\n", inpkt->optlen);
#endif
    if (inpkt->optlen < 6) return;
#if DEBUG
    fprintf(stderr, "%d.%d.%d.%d\n", options[0], options[1], options[2], options[3]);
#endif

    // check the magic cookie
    if (!(options[0] == 99 && options[1] == 130
                && options[2]== 83 && options[3] == 99)) {
        return;
    }

    i = 4;

    while (1) {
        CHKOPTLEN(2);
        tag = options[i++];
        if (tag == 0) continue;
        if (tag == 255) goto END;

        len = options[i++];

        CHKOPTLEN(len);

        switch (tag) {
            case 1:
                // Subnet Mask
                if (len != 4) {
                    fprintf(stderr, "Malformed len in subnet mask tag: Should be 4 but is %d\n", len);
                    return;
                }

                ip.a[0] = options[i++]; ip.a[1] = options[i++]; ip.a[2] = options[i++]; ip.a[3] = options[i++];

                printf("Subnet Mask: %d.%d.%d.%d\n", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
                break;
            case 3:
                // Default Gateway
                if (len < 4) {
                    fprintf(stderr, "Malformed len in router tag: Should 4 or greater but is %d\n", len);
                    return;
                }

                if (len % 4 != 0) {
                    fprintf(stderr, "Malformed len in router tag: Should be a multiple of 4 but is %d\n", len);
                    return;
                }

                len /= 4;
                for (j = 0; j < len; j++) {
                    ip.a[0] = options[i++];
                    ip.a[1] = options[i++];
                    ip.a[2] = options[i++];
                    ip.a[3] = options[i++];

#if DEBUG
                    printf("Router %d: %d.%d.%d.%d\n", j + 1, ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
#endif
                }
                break;
            case 6:
                // DNS Servers
                if (len < 4) {
                    fprintf(stderr, "Malformed len in DNS tag: Should 4 or greater but is %d\n", len);
                    return;
                }

                if (len % 4 != 0) {
                    fprintf(stderr, "Malformed len in DNS tag: Should be a multiple of 4 but is %d\n", len);
                    return;
                }

                len /= 4;
                for (j = 0; j < len; j++) {
                    ip.a[0] = options[i++];
                    ip.a[1] = options[i++];
                    ip.a[2] = options[i++];
                    ip.a[3] = options[i++];

#if DEBUG
                    printf("DNS Server %d: %d.%d.%d.%d\n", j + 1, ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
#endif
                }
                break;
                break;
            case 12:
                // Host Name Option
                memcpy(buffer, &options[i], len);
                buffer[len] = '\0';
#if DEBUG
                printf("Hostname: %s\n", buffer);
#endif
                i += len;
                break;
            case 50:
                // Requested IP
                if (len != 4) {
                    fprintf(stderr, "Malformed len in requested IP tag: Should be 4 but is %d\n", len);
                    return;
                }

                ip.a[0] = options[i++];
                ip.a[1] = options[i++];
                ip.a[2] = options[i++];
                ip.a[3] = options[i++];

                printf("Requested IP: %d.%d.%d.%d\n", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
                break;
                break;
            case 51:
                // Lease Time in Seconds
                lease = *((guint32*) &options[i]);
                lease = ntohl(lease);

                printf("Lease: %ld\n", (long) lease);
                i += len;
                break;
            case 53:
                // DHCP Message Type
                msgtype = options[i++];
                printf("MSG TYPE: %d\n", msgtype);
                printf("MSG TYPE: %s\n", msgtypes[msgtype]);
                break;
            case 54:
                // Server Identifier
                if (len != 4) {
                    fprintf(stderr, "Malformed len in server identifier tag: Should be 4 but is %d\n", len);
                    return;
                }

                ip.a[0] = options[i++];
                ip.a[1] = options[i++];
                ip.a[2] = options[i++];
                ip.a[3] = options[i++];

                printf("Server Identifier: %d.%d.%d.%d\n", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
                break;
            case 55:
                printf("DHCP options: ");
                for (j = 0; j < len; j++) {
                    if (j != 0) printf(", ");
                    printf("%d", options[i++]);
                }
                printf("\n");
                break;
            default:
                fprintf(stderr, "ERROR: Unknown DHCP Option Tag: %d\n", tag);
                // skip over this tag
                i += len;
        }
    }

END:

    // we serve only MACs we know
    fprintf(stderr, "Lookup of MAC %x:%x:%x:%x:%x:%x in VLAN %d\n",
            srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5], inpkt->vlan);
    client = lookup_client(conf, inpkt->vlan, srcmac);
    if (client == NULL) return;
    fprintf(stderr, "Lookup successful\n");

    if (msgtype == DHCPDISCOVER) {
        send_offer(p, inpkt, client);
    } else if (msgtype == DHCPREQUEST) {
        send_ack(p, inpkt, client);
    }
}
