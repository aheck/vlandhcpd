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

#ifndef __PKTBUF_H__
#define __PKTBUF_H__

#include <glib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "global.h"
#include "arp.h"
#include "dhcp.h"

#define PKT_IFACE_MAX_LEN 8

/* Contains everything we need to build a packet */
struct pktbuf {
    int tagged;
    gchar iface[PKT_IFACE_MAX_LEN];
    guint16 vlan;
    struct ethhdr *eth_header;
    struct ethhdrvlan *eth_header_vlan;
    struct arp_pkt *arp_packet;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct dhcp_pkt *dhcp_packet;
    guint32 pktlen;
    guint32 dhcplen;
    guint32 optlen;
    unsigned char buffer[1518];
    unsigned char *data;
};

unsigned long csum_update(unsigned short *buf, int nwords, unsigned long sum);
unsigned short csum_finalize(unsigned long sum);
unsigned short csum(unsigned short *buf, int nwords);
void pktbuf_csum(struct pktbuf *pkt);
void pktbuf_init_layer2(struct pktbuf *pkt, struct pktbuf *inpkt, int hproto);
int pktbuf_send(pcap_t *p, struct pktbuf *pkt);
gboolean pktbuf_send_on_vlan_iface(pcap_t *p, struct pktbuf *pkt);
int pktbuf_parse(struct pktbuf *pkt, const gchar *iface, const guchar *packet,
        struct pcap_pkthdr *header);
gboolean pktbuf_strip_vlan_tag(struct pktbuf *pkt);
gboolean pktbuf_unstrip_vlan_tag(struct pktbuf *pkt);

#endif /* __PKTBUF_H__ */
