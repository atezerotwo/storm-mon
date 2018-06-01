#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <arpa/inet.h>

#define VLAN_VID_MASK	0x0fff		/* VLAN Identifier */
#define ETHER_ADDR_LEN	6
#define ETHER_TYPE_LEN	2
#define ETHER_CRC_LEN	4
#define ETHER_HDR_LEN	(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_VLAN  0x8100 /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_ARP	0x0806 /* Address resolution */

int packetcount = 0;

void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    printf("\r Packets:%u", packetcount++);
}
