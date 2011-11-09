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

#include "pktbuf.h"

unsigned long csum_update(unsigned short *buf, int nwords, unsigned long sum) {
    for (; nwords > 0; nwords--)
        sum += *buf++;
    return sum;
}

unsigned short csum_finalize(unsigned long sum) {
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum=0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

void pktbuf_csum(struct pktbuf *pkt) {
    unsigned char udp_pseudo[12];
    unsigned char *buffer;
    unsigned long udpsum;
    int udp_len;

    // IP checksum
    pkt->ip_header->check = 0;
    pkt->ip_header->check = csum((unsigned short *) pkt->ip_header, pkt->ip_header->ihl * 2);

    // UDP checksum
    pkt->udp_header->check = 0;
    udpsum = 0;

    // build the UDP pseudo header
    memset(udp_pseudo, 0, sizeof(udp_pseudo));
    memcpy(&udp_pseudo, &pkt->ip_header->saddr, 4);
    memcpy(&udp_pseudo[4], &pkt->ip_header->daddr, 4);
    udp_pseudo[8] = 0;
    udp_pseudo[9] = pkt->ip_header->protocol;
    memcpy(&udp_pseudo[10], &pkt->udp_header->len, 2);

    // checksum the pseudo header
    udpsum = csum_update((unsigned short *) udp_pseudo, 6, udpsum);

    udp_len = sizeof(struct udphdr) + pkt->dhcplen + pkt->optlen;

    // checksum the UDP header and payload
    if (udp_len % 2 == 1) {
        buffer = (unsigned char *) pkt->udp_header;
        buffer[udp_len] = 0;
        udp_len++;
    }

    udpsum = csum_update((unsigned short *) pkt->udp_header, udp_len / 2, udpsum);
    pkt->udp_header->check = csum_finalize(udpsum);
}

/*
 * Copies the VLAN tagging or lack thereof from one struct pktbuf to another and
 * sets up the eth_header and eth_header_vlan pointers accordingly
 */
void pktbuf_init_layer2(struct pktbuf *pkt, struct pktbuf *inpkt, int hproto) {
    pkt->tagged = inpkt->tagged;
    pkt->data = pkt->buffer;

    if (inpkt->tagged) {
        pkt->eth_header_vlan = (struct ethhdrvlan *) &pkt->buffer;
        pkt->eth_header_vlan->h_proto = htons(hproto);
        memcpy(pkt->buffer, inpkt->buffer, sizeof(struct ethhdrvlan));
    } else {
        pkt->eth_header = (struct ethhdr *) &pkt->buffer;
        pkt->eth_header->h_proto = htons(hproto);
    }
}

int pktbuf_send(pcap_t *p, struct pktbuf *pkt) {
    int len;

    len = pcap_inject(p, pkt->data, pkt->pktlen);
    if (len < 0) {
        perror("ERROR");
        return -1;
    }

#if DEBUG
    fprintf(stderr, "Bytes written: %d\n", len);
#endif

    return 0;
}

gboolean pktbuf_strip_vlan_tag(struct pktbuf *pkt) {
    guchar buffer[4];

    if (!pkt->tagged) {
        return FALSE;
    }

    memcpy(buffer, &pkt->eth_header_vlan->tpid, 4);
    memmove(pkt->buffer + 4, pkt->buffer, ETH_ALEN * 2);
    memcpy(pkt->buffer, buffer, 4);
    pkt->eth_header = (struct ethhdr *) ((void *) pkt->buffer + 4);
    pkt->data = (unsigned char *) pkt->eth_header;
    pkt->eth_header_vlan = NULL;
    pkt->tagged = FALSE;
    pkt->pktlen -= 4;

    return TRUE;
}

gboolean pktbuf_unstrip_vlan_tag(struct pktbuf *pkt) {
    guchar buffer[4];

    if (pkt->tagged) {
        return FALSE;
    }

    if (pkt->eth_header_vlan != (void *) (pkt->buffer + 4)) {
        return FALSE;
    }

    memcpy(buffer, pkt->buffer, 4);
    memmove(pkt->buffer, pkt->eth_header_vlan, ETH_ALEN * 2);
    memcpy(&pkt->eth_header_vlan->tpid, buffer, 4);
    pkt->eth_header_vlan = (struct ethhdrvlan *) pkt->buffer;
    pkt->tagged = FALSE;
    pkt->pktlen += 4;

    return TRUE;
}

gboolean pktbuf_send_on_vlan_iface(pcap_t *p, struct pktbuf *pkt) {
    gboolean result = TRUE;
    int len;
    pcap_t *pcap;
    GString *iface;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!pkt->tagged) {
        fprintf(stderr, "frame tagged!!!\n");
        return FALSE;
    }

    iface = g_string_new("");
    g_string_printf(iface, "%s.%d", pkt->iface, pkt->vlan);

    pcap = pcap_open_live(iface->str, FRAME_SIZE, 1, 0, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Couldn't open network interface %s: %s\n", iface->str, errbuf);
        result = FALSE;
        goto error;
    }

    pktbuf_strip_vlan_tag(pkt);

    len = pcap_inject(pcap, pkt->data, pkt->pktlen);
    if (len < 0) {
        perror("ERROR");
        result = FALSE;
    }

    pktbuf_unstrip_vlan_tag(pkt);

error:

    g_string_free(iface, TRUE);
    pcap_close(pcap);

    return result;
}

/*
 * Parse a packet buffer received over the wire into a struct pktbuf
 */
int pktbuf_parse(struct pktbuf *pkt, const gchar *iface, const guchar *packet,
        struct pcap_pkthdr *header) {
    union ip_address ipsrc;
    union ip_address ipdst;
    union ip_address ciaddr;
    union ip_address yiaddr;
    union ip_address siaddr;
    union ip_address giaddr;
    void *next;
    guint16 vlanid;
    guint16 srcport;
    guint16 dstport;

    fprintf(stderr, "interface: %s\n", iface);
    g_strlcpy(pkt->iface, iface, PKT_IFACE_MAX_LEN);
    memcpy(&pkt->buffer, packet, header->len);
    pkt->pktlen = header->len;
    pkt->eth_header = (struct ethhdr*) pkt->buffer;

    // decide if frame is tagged
    if (pkt->eth_header->h_proto == htons(ETH_P_8021Q)) {
        pkt->tagged = 1;
        pkt->eth_header_vlan = (struct ethhdrvlan *) pkt->buffer;
        vlanid = (ntohs(pkt->eth_header_vlan->tci) << 4) >> 4;
        pkt->vlan = vlanid;
        next = (((void*) pkt->eth_header_vlan) + sizeof(struct ethhdrvlan));

        if (pkt->eth_header_vlan->h_proto == htons(ETH_P_IP)) {
            pkt->ip_header = (struct iphdr*) next;
        } else if (pkt->eth_header_vlan->h_proto != htons(ETH_P_ARP)) {
            pkt->arp_packet = (struct arp_pkt *) next;
        } else {
            return -1;
        }
    } else {
        pkt->tagged = 0;
        pkt->vlan = DEFAULT_VLAN;
        next = (((void*) pkt->eth_header) + sizeof(struct ethhdr));

        if (pkt->eth_header->h_proto == htons(ETH_P_IP)) {
            pkt->ip_header = (struct iphdr *) next;
        } else if (pkt->eth_header->h_proto != htons(ETH_P_IP)) {
            pkt->arp_packet = (struct arp_pkt *) next;
        } else {
            return -1;
        }
    }

    if (pkt->arp_packet) {
        struct arp_pkt *arp;
        arp = pkt->arp_packet;
#if DEBUG
        fprintf(stderr, "ARP Packet:\n");
        fprintf(stderr, "htype: %d\n", ntohs(arp->htype));
        fprintf(stderr, "atype: %d\n", ntohs(arp->atype));
        fprintf(stderr, "hsize: %d\n", arp->hsize);
        fprintf(stderr, "asize: %d\n", arp->psize);
        fprintf(stderr, "op: %d\n", ntohs(arp->op));
        fprintf(stderr, "srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                arp->srcmac[0], arp->srcmac[1], arp->srcmac[2], arp->srcmac[3],
                arp->srcmac[4], arp->srcmac[5]);
        fprintf(stderr, "srcip: %d.%d.%d.%d\n", arp->srcip.a[0],
                arp->srcip.a[1], arp->srcip.a[2], arp->srcip.a[3]);
        fprintf(stderr, "dstmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                arp->dstmac[0], arp->dstmac[1], arp->dstmac[2], arp->dstmac[3],
                arp->dstmac[4], arp->dstmac[5]);
        fprintf(stderr, "dstip: %d.%d.%d.%d\n", arp->dstip.a[0],
                arp->dstip.a[1], arp->dstip.a[2], arp->dstip.a[3]);
#endif
        return 0;
    }

    ipsrc.addr = pkt->ip_header->saddr;
    ipdst.addr = pkt->ip_header->daddr;

    if (pkt->ip_header->protocol != IPPROTO_UDP) {
        return -1;
    }

    pkt->udp_header = (struct udphdr*) (((void*) pkt->ip_header) + pkt->ip_header->ihl * 4);
    srcport = ntohs(pkt->udp_header->source);
    dstport = ntohs(pkt->udp_header->dest);

    if ((srcport == DHCP_PORT_CLIENT || srcport == DHCP_PORT_SERVER)
            && (dstport == DHCP_PORT_SERVER || dstport == DHCP_PORT_CLIENT)) {
        pkt->dhcp_packet = (struct dhcp_pkt*) (((void*) pkt->udp_header) + sizeof (struct udphdr));
        pkt->dhcplen = pkt->pktlen - sizeof(struct ethhdr) - pkt->ip_header->ihl * 4 - sizeof(struct udphdr);

#if DEBUG
        fprintf(stderr, "Tagged Frame: %d\n", vlanid);

        printf("Caught DHCP packet: %d.%d.%d.%d:%d => %d.%d.%d.%d:%d\n",
                ipsrc.a[0], ipsrc.a[1], ipsrc.a[2], ipsrc.a[3], srcport,
                ipdst.a[0], ipdst.a[1], ipdst.a[2], ipdst.a[3], dstport);

        printf("Ethernet addresses: %x:%x:%x:%x:%x:%x =>: %x:%x:%x:%x:%x:%x\n",
                pkt->eth_header->h_source[0], pkt->eth_header->h_source[1],
                pkt->eth_header->h_source[2], pkt->eth_header->h_source[3],
                pkt->eth_header->h_source[4], pkt->eth_header->h_source[5],
                pkt->eth_header->h_dest[0], pkt->eth_header->h_dest[1],
                pkt->eth_header->h_dest[2], pkt->eth_header->h_dest[3],
                pkt->eth_header->h_dest[4], pkt->eth_header->h_dest[5]);
#endif

        ciaddr.addr = pkt->dhcp_packet->ciaddr;
        yiaddr.addr = pkt->dhcp_packet->yiaddr;
        siaddr.addr = pkt->dhcp_packet->siaddr;
        giaddr.addr = pkt->dhcp_packet->giaddr;

#if DEBUG
        printf("DHCP packet:\n");
        printf("op: %d\n", pkt->dhcp_packet->op);
        printf("htype: %d\n", pkt->dhcp_packet->htype);
        printf("hlen: %d\n", pkt->dhcp_packet->hlen);
        printf("hops: %d\n", pkt->dhcp_packet->hops);
        printf("xid: 0x%x\n", ntohl(pkt->dhcp_packet->xid));
        printf("sec: %x\n", ntohs(pkt->dhcp_packet->sec));
        printf("flags: 0x%x\n", ntohs(pkt->dhcp_packet->flags));
        printf("ciaddr: %d.%d.%d.%d\n", ciaddr.a[0], ciaddr.a[1], ciaddr.a[2], ciaddr.a[3]);
        printf("yiaddr: %d.%d.%d.%d\n", yiaddr.a[0], yiaddr.a[1], yiaddr.a[2], yiaddr.a[3]);
        printf("siaddr: %d.%d.%d.%d\n", siaddr.a[0], siaddr.a[1], siaddr.a[2], siaddr.a[3]);
        printf("giaddr: %d.%d.%d.%d\n", giaddr.a[0], giaddr.a[1], giaddr.a[2], giaddr.a[3]);
        printf("chaddr: %x:%x:%x:%x:%x:%x\n", pkt->dhcp_packet->chaddr[0], pkt->dhcp_packet->chaddr[1],
                pkt->dhcp_packet->chaddr[2], pkt->dhcp_packet->chaddr[3], pkt->dhcp_packet->chaddr[4],
                pkt->dhcp_packet->chaddr[5]);
        printf("sname: %s\n", pkt->dhcp_packet->sname);
        printf("file: %s\n", pkt->dhcp_packet->file);
#endif

        pkt->dhcplen = sizeof(struct dhcp_pkt);
        pkt->optlen = pkt->pktlen - sizeof(struct iphdr) - sizeof(struct udphdr) - pkt->dhcplen;
        if (pkt->tagged) {
            pkt->optlen -= sizeof(struct ethhdrvlan);
        } else {
            pkt->optlen -= sizeof(struct ethhdr);
        }
    }

#if DEBUG
    printf("\n");
#endif

    return 0;
}
