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

#include "arp.h"

void handle_arp(struct server_conf *conf, pcap_t *p, struct pktbuf *inpkt) {
    union ip_address reqip;
    GList *cur;
    struct group_config *group;
    struct pktbuf *pkt;

    if (inpkt->arp_packet->op != htons(ARP_OP_REQUEST) ||
            inpkt->arp_packet->htype != htons(1) ||
            inpkt->arp_packet->atype != htons(ETH_P_IP) ||
            inpkt->arp_packet->hsize != ETH_ALEN ||
            inpkt->arp_packet->psize != 4) {
#if DEBUG
        fprintf(stderr, "Invalid ARP request\n");
#endif
        return;
    }

    reqip.addr = 0;

    for (cur = g_list_first(conf->groups); cur; cur = g_list_next(cur)) {
        group = (struct group_config *) cur->data;
        union ip_address ip;
        ip.addr = inpkt->arp_packet->dstip.addr;
        if (group->server_ip.addr == inpkt->arp_packet->dstip.addr) {
            fprintf(stderr, "MATCH\n");
            reqip.addr = group->server_ip.addr;
            //break;
        }
    }

    if (reqip.addr == 0) {
#if DEBUG
        fprintf(stderr, "Don't answering ARP reqeust because unknown IP\n");
#endif
        return;
    }

    pkt = g_new0(struct pktbuf, 1);
    pktbuf_init_layer2(pkt, inpkt, ETH_P_ARP);

    if (pkt->tagged) {
        memcpy(pkt->eth_header_vlan->h_source, conf->self_mac, ETH_ALEN);
        memcpy(pkt->eth_header_vlan->h_dest, inpkt->eth_header_vlan->h_source, ETH_ALEN);
        pkt->pktlen = sizeof(struct ethhdrvlan) + sizeof(struct arp_pkt);
        pkt->arp_packet = (struct arp_pkt *) (pkt->buffer + sizeof(struct ethhdrvlan));
    } else {
        memcpy(pkt->eth_header->h_source, conf->self_mac, ETH_ALEN);
        memcpy(pkt->eth_header->h_dest, inpkt->eth_header->h_source, ETH_ALEN);
        pkt->pktlen = sizeof(struct ethhdr) + sizeof(struct arp_pkt);
        pkt->arp_packet = (struct arp_pkt *) (pkt->buffer + sizeof(struct ethhdr));
    }

    pkt->arp_packet->htype = htons(1);
    pkt->arp_packet->atype = htons(ETH_P_IP);
    pkt->arp_packet->hsize = ETH_ALEN;
    pkt->arp_packet->psize = 4;
    pkt->arp_packet->op = htons(ARP_OP_REPLY);
    memcpy(pkt->arp_packet->srcmac, conf->self_mac, ETH_ALEN);
    pkt->arp_packet->srcip.addr = reqip.addr;
    memcpy(pkt->arp_packet->dstmac, inpkt->arp_packet->srcmac, ETH_ALEN);
    pkt->arp_packet->dstip = inpkt->arp_packet->srcip;

    pktbuf_send(p, pkt);
    fprintf(stderr, "Sent ARP reply\n");
    g_free(pkt);
}
