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

#ifndef __DHCP_H__
#define __DHCP_H__

#include "global.h"
#include "pktbuf.h"

#define DHCP_PORT_SERVER 67
#define DHCP_PORT_CLIENT 68

#define DHCP_LEASE_INFINITE 0xffffffff

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

extern const char *msgtypes[9];

struct pktbuf;

struct dhcp_pkt {
    guint8 op; // Message op code / message type.  1 = BOOTREQUEST, 2 = BOOTREPLY
    guint8 htype; // Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
    guint8 hlen; // Hardware address length (e.g.  '6' for 10mb ethernet).
    guint8 hops; // Client sets to zero, optionally used by relay agents when booting via a relay agent.
    guint32 xid; // Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
    guint16 sec; // Filled in by client, seconds elapsed since client began address acquisition or renewal process.
    guint16 flags; // Flags (see figure 2).
    guint32 ciaddr; // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
    guint32 yiaddr; // 'your' (client) IP address.
    guint32 siaddr; // IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    guint32 giaddr; // Relay agent IP address, used in booting via a relay agent.
    guint8 chaddr[16]; // Client hardware address.
    unsigned char sname[64]; // Optional server host name, null terminated string.
    unsigned char file[128]; // Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
    unsigned char options[]; // Optional parameters field.  See the options documents for a list of defined options.
};

struct client_conf* lookup_client(struct server_conf *conf, int vlan,
        unsigned char mac[ETH_ALEN]);

void handle_dhcp(struct server_conf *conf, pcap_t *p, struct pktbuf *inpkt);

#endif /* __DHCP_H__ */
