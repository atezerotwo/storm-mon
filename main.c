//credit tcpdump
//credit wireshark

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <getopt.h>
#include "options.h"
#include "handler.h"

char op;
int Dflag;
int Vflag;
int Hflag;
int Cflag;


/* see netdisect on tcpdump */
typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint24_t[3];
typedef unsigned char nd_uint32_t[4];
typedef unsigned char nd_uint40_t[5];
typedef unsigned char nd_uint48_t[6];
typedef unsigned char nd_uint56_t[7];
typedef unsigned char nd_uint64_t[8];
typedef unsigned char nd_byte;
typedef signed char nd_int8_t[1];
typedef unsigned char nd_int32_t[4];
typedef unsigned char nd_int64_t[8];


#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define SIZE_LLC 3
#define DSAP_STP 0x42
#define IEEE_802_3_MAX_LEN 0x5DC

#define ETHERNET_II 0
#define ETHERNET_802_2 1
#define ETHERNET_802_3 2
#define ETHERNET_SNAP 3

/* Ethernet header */
struct ethernet_header
{
    unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_int16_t ether_type;                      /* IP? ARP? RARP? etc */
};
/* LLC header after ethernet header */
struct llc_hdr
{
    unsigned char dsap;
    unsigned char ssap;
    unsigned char ctrl;
};

/* STP BPDU */
struct stp_bpdu_ {
    nd_uint16_t protocol_id;
    nd_uint8_t  protocol_version;
    nd_uint8_t  bpdu_type;
    nd_uint8_t  flags;
    nd_byte     root_id[8];
    nd_uint32_t root_path_cost;
    nd_byte     bridge_id[8];
    nd_uint16_t port_id;
    nd_uint16_t message_age;
    nd_uint16_t max_age;
    nd_uint16_t hello_time;
    nd_uint16_t forward_delay;
    nd_uint8_t  v1_length;
};


struct pcap_pkthdr header; /* The header that pcap gives us */
struct pcap_stat stats;
const unsigned char *packet; /* The actual packet */

/* argument parser config */
static const struct option longopts[] = {
    {"list-interfaces", no_argument, NULL, 'D'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};


int main(int argc, char **argv)
{

    //parse otions from command line using getopt_long
    while ((op = getopt_long(argc, argv, "dvhc", longopts, NULL)) != -1)
        switch (op)
        {

        case 'd':
            Dflag++;
            break;

        case 'v':
            Vflag++;
            break;

        case 'h':
            Hflag++;
            break;

        case 'c':
            Cflag++;
            break;
        }

    //check for device list option
    if (Dflag)
        show_devices_and_exit();

    //check for version option
    if (Vflag)
        print_version_and_exit();

    if (Hflag)
        print_help_and_exit();

    if (Cflag)
    {

        /*pcap stuff*/
        pcap_t *adhandle = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        char *dev = "ens38";
        char packet_filter[] = "stp";
        struct bpf_program filtercode;

        //printf("Device: %s\n", dev);

        adhandle = pcap_open_live(dev, 72, 1, 0, errbuf);

        if (adhandle == NULL)
        {
            fprintf(stderr, "\nUnable to open the adapter. it is not supported by libpcap\n");
            fprintf(stderr, "%s", errbuf);
            /* Free the device list */
            //pcap_freealldevs(alldevs);
            return -1;
        }

        //compile the filter
        if (pcap_compile(adhandle, &filtercode, packet_filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
            //pcap_freealldevs(alldevs);
            return -1;
        }

        if (pcap_setfilter(adhandle, &filtercode) < 0)
        {
            fprintf(stderr, "\nError setting the filter.\n");
            /* Free the device list */
            //pcap_freealldevs(alldevs);
            return -1;
        }

        printf("started on %s ...\n", dev);
        //pcap_loop(adhandle, 0, packet_handler, NULL);

        unsigned int pcount = 0;
        int len = 0;
        int statret;

        int ethhdr_type;

        const struct ethernet_header *ethernet;
        const struct stp_bpdu_ *payload;
        const struct llc_hdr *llc;

        while (1)
        {

            packet = pcap_next(adhandle, &header);

            //statret = pcap_stats(adhandle, &stats);

            ethernet = (struct ethernet_header *)(packet);
            llc = (struct llc_hdr *)(packet + SIZE_ETHERNET);
            payload = (struct stp_bpdu_ *)(packet + SIZE_ETHERNET + SIZE_LLC);

            int n = 60, i = 0;
            unsigned char* byte_array = packet;

            while (i < n)
            {
                printf("%02X ", (unsigned)byte_array[i]);
                i++;
            }

            if (ntohs(ethernet->ether_type) <= IEEE_802_3_MAX_LEN)
            {
                ethhdr_type = ETHERNET_802_2;
                printf("\n802.2 packet: length:%d\n", ntohs(ethernet->ether_type));

                if (llc->dsap == DSAP_STP)
                {
                    printf("STP packet: path cost %d\n", ntohs(payload->root_path_cost));
                }
            }

            /* Print its length */
            //printf("Jacked a packet with length of [%d]\n", header.len);
            printf("Packets seen: %u with a payload length of: %#06x(%u)\n", pcount++, ntohs(ethernet->ether_type), ntohs(ethernet->ether_type));
            printf("> Successfully received Dest MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (unsigned char)ethernet->ether_dhost[0],
                   (unsigned char)ethernet->ether_dhost[1],
                   (unsigned char)ethernet->ether_dhost[2],
                   (unsigned char)ethernet->ether_dhost[3],
                   (unsigned char)ethernet->ether_dhost[4],
                   (unsigned char)ethernet->ether_dhost[5]);
            printf("> Successfully received Srce MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (unsigned char)ethernet->ether_shost[0],
                   (unsigned char)ethernet->ether_shost[1],
                   (unsigned char)ethernet->ether_shost[2],
                   (unsigned char)ethernet->ether_shost[3],
                   (unsigned char)ethernet->ether_shost[4],
                   (unsigned char)ethernet->ether_shost[5]);
            printf("Payload type %#06x\n", payload->protocol_id);
            //printf("\rPackets seen:%u\t recv:%u\t drop:%u\t ifdrop:%u", pcount++, stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
            fflush(stdout);
            /* And close the session */
        }

        //pcap_close(adhandle);
    }

    printf("no option selected\n");

    return 0;
}
