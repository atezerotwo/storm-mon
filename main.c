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

static const struct option longopts[] = {
    {"list-interfaces", no_argument, NULL, 'D'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

struct pcap_pkthdr header;	/* The header that pcap gives us */
const unsigned char *packet;		/* The actual packet */

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

        packet = pcap_next(adhandle, &header);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
		pcap_close(adhandle);
    }

    printf("no option selected\n");

    return 0;
}
