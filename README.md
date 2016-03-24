#vlandhcpd#

vlandhcpd is a VLAN-aware DHCP server. This means that you can configure it
to run on a trunking device and assign network configuration to clients in
different VLANs, as long as their DHCP requests are visible on the trunking
device.

The server accomplishes this by directly parsing the tagged or untagged
ethernet headers, as well as the headers of the IP, UDP and DHCP protocol
layers. When sending back a response to a client the server sends the answer
back over the trunking device with the same VLAN tag as the one used by the
client request.

If you configure no VLANs or use vlandhcpd on a non-trunking interface it
will act as a normal DHCP server.

##Dependencies##

- cmake
- glib 2.0
- libpcap

##Usage##

When you start vlandhcpd you need to supply the path to the configuration
file as well as the name of the trunking interface:

> vlandhcpd dhcpd.conf eth0

##Configuration##

A valid *dhcpd.conf* configuration file for vlandhcpd looks like the following example:

```
serverip 192.168.1.155
lease 86400

nameserver 213.191.92.86
nameserver 45.191.92.86
nameserver 62.109.123.196
netmask 24

gateway 192.168.1.1

client 192.168.1.190 mac 00:24:54:5f:61:98
client 192.168.1.191 mac 00:15:17:ee:b6:f1
client 192.168.1.192 mac 00:15:17:ee:56:b5

VLAN 55

client 192.168.1.193 mac 00:26:0a:16:b3:99
client 192.168.1.194 mac c8:2a:14:09:54:5a
```

The file is devided into sections. A new section starts with the keyword VLAN
followed by a VLAN tag number. If you don't specify a VLAN at the beginning of
the file the section is assumed to configure DHCP for untagged packets.

Now you can specify network properties like, IP of the DHCP server (this will
be spoofed by ARP spoofing to simulate a "real" DHCP server to clients), the
lease time, a list of nameservers the netmask and the IP of the gateway.

After specifying those global netwide properties you can configure a list of
static MAC address to client IP mappings.

Remember that all the netwide settings are reused in the all the following
sections until you redefine them.

##Contact##

Andreas Heck <aheck@gmx.de>
