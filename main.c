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
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_int16_t ether_type;               /* IP? ARP? RARP? etc */
};

struct llc_hdr
{
    u_char dsap;
    u_char ssap;
    u_char ctrl;
};

struct stp_root_id
{
    u_char root_priority;
    u_char extension;
    u_char root_addr[ETHER_ADDR_LEN];
};

struct stp_payload
{
    u_short protcol_id;
    u_char version;
    u_char type;
    u_char flags;
    struct stp_root_id root_id;
    u_int16_t root_cost;
    struct stp_root_id sender_id;;
    u_char port[2];
    u_short message_age;
    u_short max_age;
    u_short forward_delay;
};

struct stp_bpdu_ {
    u_int16_t protocol_id;
    u_int8_t  protocol_version;
    u_int8_t  bpdu_type;
    u_int8_t  flags;
    u_char    root_id[8];
    u_int32_t root_path_cost;
    u_char     bridge_id[8];
    u_int16_t port_id;
    u_int16_t message_age;
    u_int16_t max_age;
    u_int16_t hello_time;
    u_int16_t forward_delay;
    u_int8_t  v1_length;
};

static const struct option longopts[] = {
    {"list-interfaces", no_argument, NULL, 'D'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

struct pcap_pkthdr header; /* The header that pcap gives us */
struct pcap_stat stats;
const unsigned char *packet; /* The actual packet */

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

            if (ntohs(ethernet->ether_type) <= IEEE_802_3_MAX_LEN)
            {
                ethhdr_type = ETHERNET_802_2;
                printf("802.2 packet: length:%d\n", ntohs(ethernet->ether_type));

                if (llc->dsap == DSAP_STP)
                {
                    printf("STP packet\n");
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
