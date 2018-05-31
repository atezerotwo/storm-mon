#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <getopt.h>
#include "options.h"

char op;
int Dflag;
int Vflag;
int Hflag;
int Cflag;

static const struct option longopts[] = {
	{ "list-interfaces", no_argument, NULL, 'D' },
    { "version", no_argument, NULL, 'v' },
    { "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};


int main(int argc, char **argv){

  //parse otions from command line using getopt_long
  while ((op = getopt_long(argc, argv, "dvhc", longopts, NULL)) != -1)
		switch (op) {

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

    printf("no option selected\n");
    
    return 0;

}


