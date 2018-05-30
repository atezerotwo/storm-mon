#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <getopt.h>
#include "options.h"

//exits monitor
void
exit_monitor(int status){
	exit(status);
}

//prints devices and then exits
void
show_devices_and_exit(void){
    char errorbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int j = 1;

    if (pcap_findalldevs(&alldevs, errorbuf) == -1){
        fprintf(stderr, "Could not get device list: %s.", errorbuf);
        return;
    }

    //print header
    printf("Index\tDevice\tDescription\n");
    printf("-----\t------\t-----------\n");

    //print name and description for each device
    for (dev = alldevs; dev != nullptr; dev = dev->next, j++)
    {
        printf("%5d", j);
        printf("\t%s", dev->name);
        if(dev->description){
        printf("\t%s\n", dev->description);
        }else
        printf("\t(No Description Available)\n");
    }

    //free devices
    pcap_freealldevs(alldevs);
    exit_monitor(0);
}

void
print_version_and_exit(){
    printf("Version 0.1\n");
    exit_monitor(0);
}

void
print_help_and_exit(void){
    printf("Monitor\n");
    printf("-------\n\n");
    printf("No options specified\n\n");
    printf("-D for device list\n");
    printf("-v for version info\n\n");
}