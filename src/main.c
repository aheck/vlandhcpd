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
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <errno.h>
#include <pcap.h>
#include <glib.h>

#include "global.h"
#include "pktbuf.h"
#include "arp.h"
#include "dhcp.h"

struct server_conf *conf = NULL;
char *config_file;
int reload = 0;

guint mac_hash(gconstpointer v) {
    int i;
    guint hash = 5381;
    gint c;
    char *mac = (char *) v;

    for (i = 0; i < ETH_ALEN; i++) {
        c = mac[i];
        hash = hash * 33 + c;
    }

    return hash;
}

gboolean mac_equal(gconstpointer a, gconstpointer b) {
    if (memcmp(a, b, ETH_ALEN) == 0) return TRUE;
    return FALSE;
}

void norm_line(char *line, int len) {
    int i;
    int numspace = 0;
    int nonspace = 0;

    for (i = 0; i < len && line[i] != '\0'; i++) {
        if (isspace(line[i])) {
            numspace++;
        } else {
            if (numspace > 1 && nonspace) {
                memcpy(&line[i - (numspace - 1)], &line[i], len - i);
            }

            // remove leading whitespaces
            if (i > 0 && !nonspace) {
                memcpy(&line[0], &line[i], len - i);
            }

            nonspace = 1;
            numspace = 0;
        }

        if (isupper(line[i])) {
            line[i] = tolower(line[i]);
        }
    }

    // handle only whitespace lines
    if (!nonspace) line[0] = '\0';
}

void server_conf_free(struct server_conf *conf) {
    GList *cur_group, *cur_client;
    struct group_config *group;

    for (cur_group = g_list_first(conf->groups); cur_group; cur_group = g_list_next(cur_group)) {
        group = (struct group_config *) cur_group->data;
        for (cur_client = g_list_first(group->clients); cur_client; cur_client = g_list_next(cur_client)) {
            g_free(cur_client->data);
        }

        g_list_free(group->clients);
        g_hash_table_destroy(group->client_by_mac);

        g_free(group);
    }

    g_list_free(conf->groups);
    g_hash_table_destroy(conf->group_by_vlan);

    g_free(conf);
}

void insert_group(struct server_conf *conf, struct group_config *group, int linenum) {
    if (group != NULL) {
        if (g_hash_table_lookup_extended(conf->group_by_vlan, &group->vlan, NULL, NULL)) {
            fprintf(stderr, "VLAN %d redefined on line %d\n", group->vlan, linenum);
            exit(1);
        }

        g_hash_table_insert(conf->group_by_vlan, &group->vlan, group);
    }
}

void read_config(struct server_conf *conf, char *filename) {
    FILE *fp = NULL;
    char origline[256];
    char line[sizeof(origline)];
    union ip_address ip;
    guint32 lease;
    int dnsidx = 0;
    unsigned char mac[ETH_ALEN];
    unsigned char netmask = 0;
    struct client_conf *client;
    int linenum = 0;
    int clients_seen = 1;
    struct group_config *cur_group = NULL;
    unsigned int vlan;

    conf->groups = NULL;
    fp = fopen(filename, "r");

    if (fp == NULL) {
        fprintf(stderr, "Couldn't open config file %s\n", filename);
        exit(1);
    }

#if DEBUG
    fprintf(stderr, "%s:\n\n", filename);
#endif
    while (fgets(origline, sizeof(origline), fp)) {
        linenum++;
        memcpy(line, origline, sizeof(origline));
        norm_line(line, sizeof(line));
#if DEBUG
        fprintf(stderr, "%s", line);
#endif

        if (strlen(line) == 0) continue;

        if (clients_seen && (g_str_has_prefix(line, "serverip ") ||
                    g_str_has_prefix(line, "lease ") ||
                    g_str_has_prefix(line, "nameserver ") ||
                    g_str_has_prefix(line, "vlan ") ||
                    g_str_has_prefix(line, "netmask ") ||
                    g_str_has_prefix(line, "gateway "))) {
            insert_group(conf, cur_group, linenum);

            cur_group = g_new0(struct group_config, 1);
            cur_group->vlan = DEFAULT_VLAN;
            vlan = DEFAULT_VLAN;
            cur_group->lease = 86400;
            cur_group->client_by_mac = g_hash_table_new(mac_hash, mac_equal);
            conf->groups = g_list_append(conf->groups, cur_group);
            conf->group_by_vlan = g_hash_table_new(g_int_hash, g_int_equal);
            dnsidx = 0;
            clients_seen = 0;
        }

        if (sscanf(line, "serverip %hhu.%hhu.%hhu.%hhu",
                    &ip.a[0], &ip.a[1], &ip.a[2], &ip.a[3]) == 4) {
            cur_group->server_ip.addr = ip.addr;
        } else if (sscanf(line, "lease %d", &lease) == 1) {
            cur_group->lease = lease;
        } else if (g_str_has_prefix(line, "lease infinite")) {
            cur_group->lease = DHCP_LEASE_INFINITE;
        } else if (sscanf(line, "vlan %u", &vlan) == 1) {
            if (vlan > 4095) {
                fprintf(stderr, "VLAN must be in range 0-4095 but is %d on line %d\n", vlan, linenum);
                exit(1);
            }
            cur_group->vlan = (guint16) vlan;
        } else if (sscanf(line, "nameserver %hhu.%hhu.%hhu.%hhu",
                          &ip.a[0], &ip.a[1], &ip.a[2], &ip.a[3]) == 4) {
            if (dnsidx == NUM_DNS) {
                fprintf(stderr, "Not more than %d DNS servers allowed!\n", NUM_DNS);
                exit(1);
            }
            cur_group->dns_servers[dnsidx].addr = ip.addr;
            dnsidx++;
        } else if (sscanf(line , "netmask %hhu.%hhu.%hhu.%hhu", &ip.a[0], &ip.a[1], &ip.a[2], &ip.a[3]) == 4) {
            cur_group->netmask.addr = ip.addr;
        } else if (sscanf(line , "netmask %hhu", &netmask) == 1) {
            if (netmask > 32) {
                fprintf(stderr, "Netmask must be in range 0-32 but is %d on line %d\n", netmask, linenum);
                exit(1);
            }
            cur_group->netmask.addr = htonl(0xffffffff << (32 - netmask));
        } else if (sscanf(line, "gateway %hhu.%hhu.%hhu.%hhu",
                    &ip.a[0], &ip.a[1], &ip.a[2], &ip.a[3]) == 4) {
            cur_group->router_ip.addr = ip.addr;
        } else if (sscanf(line , "client %hhu.%hhu.%hhu.%hhu mac %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                          &ip.a[0], &ip.a[1], &ip.a[2], &ip.a[3],
                          &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 10) {

            if (g_hash_table_lookup_extended(cur_group->client_by_mac, mac, NULL, NULL)) {
                fprintf(stderr, "Error on line %d: The MAC address %hhx:%hhx:%hhx:%hhx:%hhx:%hhx is already mapped to another IP\n",
                        linenum, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                exit(1);
            }

            client = (struct client_conf *) malloc(sizeof(struct client_conf));
            memset(client, 0, sizeof(struct client_conf));

            client->ip.addr = ip.addr;
            memcpy(client->mac, mac, ETH_ALEN);
            client->group = cur_group;

            cur_group->clients = g_list_append(cur_group->clients, client);
            g_hash_table_insert(cur_group->client_by_mac, client->mac, client);
            clients_seen = 1;
        } else if (line[0] == '\0' || line[0] == '#') {
            // skip empty lines as well as comment lines
        } else {
            fprintf(stderr, "Syntax error in config file in line %d: '%s'\n", linenum, origline);
            exit(0);
        }
    }

    insert_group(conf, cur_group, linenum);
    fclose(fp);
}

void mac_for_interface(char *iface, unsigned char *addr) {
    int sock;
    struct ifreq ifr;

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("ERROR");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(1);
    }

    memcpy(addr, &ifr.ifr_addr.sa_data, ETH_ALEN);

    close(sock);
}

void signal_handler(int signal) {
    if (signal == SIGHUP) {
        reload = 1;
    }
}

int main (int argc, char **argv) {
    struct pktbuf pkt;
    pcap_t *pcap;
    struct pcap_pkthdr header;
    const unsigned char *data;
    char errbuf[PCAP_ERRBUF_SIZE];
    gchar *iface_name;
    struct bpf_program filter;

    /*
     * Order in this filter is important!!!
     *
     * The non-VLAN expressions must come first, or they won't be matched!
     */
    const char *filter_exp = "arp || (udp port 67) || (vlan and arp) || (vlan and udp port 67)";

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [CONFIGFILE] [INTERFACE]\n", argv[0]);
        exit(0);
    }

    config_file = argv[1];
    iface_name = argv[2];

    pcap = pcap_open_live(iface_name, FRAME_SIZE, 1, 0, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Couldn't open network interface %s: %s\n", iface_name, errbuf);
        exit(1);
    }

    if (pcap_compile(pcap, &filter, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(1);
    }

    if (pcap_setfilter(pcap, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(1);
    }

    conf = g_new0(struct server_conf, 1);
    read_config(conf, config_file);

    mac_for_interface(iface_name, conf->self_mac);
#if DEBUG
    printf("Self MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", conf->self_mac[0],
            conf->self_mac[1], conf->self_mac[2], conf->self_mac[3],
            conf->self_mac[4], conf->self_mac[5]);
#endif

    signal(SIGHUP, signal_handler);

    while (1) {
        if (reload) {
            reload = 0;
            server_conf_free(conf);
            conf = g_new0(struct server_conf, 1);
            read_config(conf, config_file);
        }

        memset(&pkt, 0, sizeof(struct pktbuf));
        data = pcap_next(pcap, &header);
        if (pktbuf_parse(&pkt, iface_name, data, &header) != 0) continue;

        if (pkt.arp_packet) {
            handle_arp(conf, pcap, &pkt);
        } else {
            handle_dhcp(conf, pcap, &pkt);
        }
    }

    pcap_close(pcap);

    return 0;
}
