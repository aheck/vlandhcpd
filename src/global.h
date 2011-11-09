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

#ifndef __GLOBAL_H_
#define __GLOBAL_H_

#define ETH_ALEN 6

#define DEBUG 1
#define NUM_DNS 5
#define FRAME_SIZE 1518
#define DEFAULT_VLAN 1

struct ethhdrvlan {
    unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
    unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
    guint16      tpid;                   /* identifies packet as tagged */
    guint16      tci;            /* VLAN info */
    guint16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

/* Convinience union to __be32 to ip address  */
union ip_address {
    guint8 a[4];
    guint32 addr;
};

struct client_conf {
    union ip_address ip;
    unsigned char mac[ETH_ALEN];
    struct group_config *group;
};

struct group_config {
    guint16 vlan;
    union ip_address server_ip;
    union ip_address dns_servers[NUM_DNS];
    union ip_address netmask;
    union ip_address router_ip;
    guint32 lease;
    GList *clients;
    GHashTable *client_by_mac;
};

struct server_conf {
    GList *groups;
    GHashTable *group_by_vlan;
    unsigned char self_mac[ETH_ALEN];
};

extern char *iface_name;

#endif /* __GLOBAL_H_ */
