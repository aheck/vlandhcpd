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

#ifndef __ARP_H_
#define __ARP_H_

#include <pcap.h>
#include <glib.h>

#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>

#include "global.h"
#include "pktbuf.h"

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct pktbuf;

struct arp_pkt {
    guint16 htype;
    guint16 atype;
    guint8 hsize;
    guint8 psize;
    guint16 op;
    unsigned char srcmac[ETH_ALEN];
    union ip_address srcip;
    unsigned char dstmac[ETH_ALEN];
    union ip_address dstip;
} __attribute__((packed));

void handle_arp(struct server_conf *conf, pcap_t *p, struct pktbuf *inpkt);

#endif /* __ARP_H_ */
