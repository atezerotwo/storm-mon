#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include "graphite-client.h"
#include <curl/curl.h>
#include "jWrite.h"
#include <arpa/inet.h>



#define VLAN_VID_MASK	0x0fff		/* VLAN Identifier */
#define ETHER_ADDR_LEN	6
#define ETHER_TYPE_LEN	2
#define ETHER_CRC_LEN	4
#define ETHER_HDR_LEN	(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_VLAN  0x8100 /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_ARP	0x0806 /* Address resolution */

/* vlan header */
typedef struct vlan_header
{
    u_int16_t vlan_tci;		/* VLAN TCI */
    u_int16_t ether_type;	/* IP? ARP? RARP? etc */
} vlan_header;

typedef struct vlan_ethernet_header
{
    unsigned char ether_dhost[ETHER_ADDR_LEN];		/* Destination host address */
    unsigned char ether_shost[ETHER_ADDR_LEN];		/* Source host address */
    u_int16_t vlan_tpid[1];					/* ETH_P_8021Q */
    vlan_header vlan_tag[1];
} vlan_ethernet_header;

unsigned int aid = 0;
u_int32_t pkt_count = 0;
u_int16_t vlan_count = 0;

typedef struct vlan_info
{
    unsigned int vlan_id;							//vlan id
    u_int32_t vlan_pkt_cnt;					//vlan total pkt count
    u_int32_t vlan_pkt_last;
    u_int16_t vlan_pps;
    u_int64_t time;
    u_int32_t vlan_half_min_pkt_cnt;
    u_int32_t vlan_half_min_pkt_last;
    u_int32_t vlan_half_min_pps;
    u_int32_t vlan_five_min_pkt_cnt;
    u_int32_t vlan_five_min_pkt_last;
    u_int32_t vlan_five_min_pps;
} vlan_info;

struct vlan_info vnfo_array[100];
struct vlan_info vnfo_temp;

time_t refresh_stamp;
time_t half_min_stamp;
time_t five_min_stamp;
time_t start_time;
time_t general_time;

extern char graphite_server;
extern char graphite_port;
extern char graphite_string;
char gstr[80];

/* start jwrite */
char jbuffer[1024];
unsigned int jbuflen= 1024;
int jerr;
char vbuffer[10];




void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    //struct tm *ltime;
    //char timestr[16];
    vlan_ethernet_header *eh;

    time_t local_tv_sec;
    //size_t len;

    u_int16_t pkt_vid;
    u_int16_t v_type;
    u_int16_t pkt_type;

    //len = header->len;

    /* get timestamp from header */
    local_tv_sec = header->ts.tv_sec;

    /* get the packet data */
    eh = (vlan_ethernet_header *)(pkt_data);

    /* get vlan id */
    pkt_vid = ntohs(eh->vlan_tag->vlan_tci) & VLAN_VID_MASK;

    /*get ether type*/
    pkt_type = htons(eh->vlan_tpid[0]);

    /*check packet type and process*/
    switch (pkt_type)
    {
    case ETHERTYPE_IP: //NO VLAN TAG FOUND
        break;

    case ETHERTYPE_VLAN: //VLAN TAG FOUND

        v_type = ntohs(eh->vlan_tag->ether_type);
        bool exists = 0;

        pkt_count++;

        if (aid < 100 && pkt_vid)
        {
            /*check if vlan exist*/
            for (unsigned int i = 0; i <= aid; i++)
                if (vnfo_array[i].vlan_id == pkt_vid)
                {
                    /*increment vlan pkt count*/
                    vnfo_array[i].vlan_pkt_cnt++;
                    exists = 1;
                }

            /*if no vlan exists in array add it*/
            if (exists == 0)
            {

                /*add vlan to array*/
                vnfo_array[aid].vlan_id = pkt_vid;
                /*set all counters to zero*/
                vnfo_array[aid].vlan_pkt_cnt = 0;
                vnfo_array[aid].vlan_pkt_last = 0;
                vnfo_array[aid].vlan_half_min_pkt_cnt = 0;
                vnfo_array[aid].vlan_half_min_pkt_last = 0;
                vnfo_array[aid].vlan_five_min_pkt_cnt = 0;
                vnfo_array[aid].vlan_five_min_pkt_last = 0;

                /*increase array id*/
                aid++;

                /*increase vlan count*/
                vlan_count++;

            }

        }

        break;
    }

    /*1 sec stats*/

    if (local_tv_sec >= refresh_stamp + 1)
    {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");


        jwOpen( jbuffer, jbuflen, JW_OBJECT, JW_COMPACT);

        for (unsigned int i = 0; i < aid; i++)
        {
            vnfo_array[i].vlan_pps = vnfo_array[i].vlan_pkt_cnt - vnfo_array[i].vlan_pkt_last;

            sprintf(vbuffer, "%04d", vnfo_array[i].vlan_id);
            jwObj_int( vbuffer , vnfo_array[i].vlan_pps );
            vnfo_array[i].vlan_pkt_last = vnfo_array[i].vlan_pkt_cnt;
            vnfo_array[i].time = local_tv_sec;
        }

        jwEnd();

        jerr= jwClose();

        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.101.15:3000/feed");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jbuffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        refresh_stamp = local_tv_sec;
    }

    // 30 seconds average

    if (local_tv_sec >= half_min_stamp + 30)
    {

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        graphite_init("10.147.233.46", 2003);

        //open jason object
        jwOpen( jbuffer, jbuflen, JW_OBJECT, JW_COMPACT);

        //loop through all vlans to get average, send to graphite and write jason for rt console
        for (unsigned int i = 0; i < aid; i++)
        {
            vnfo_array[i].vlan_half_min_pps = (vnfo_array[i].vlan_pkt_cnt - vnfo_array[i].vlan_half_min_pkt_last) / 30;
            vnfo_array[i].vlan_half_min_pkt_last = vnfo_array[i].vlan_pkt_cnt;
            sprintf(gstr, "network.broadcast.vlan.%0*d", 4 ,vnfo_array[i].vlan_id);
            graphite_send_plain(gstr, vnfo_array[i].vlan_half_min_pps, local_tv_sec);
            gstr[0] = 0;

            //write json object
            sprintf(vbuffer, "%04d", vnfo_array[i].vlan_id);
            jwObj_int( vbuffer , vnfo_array[i].vlan_half_min_pps );

        }

        //close jason
        jwEnd();
        jerr= jwClose();

        //post jason to nodejs
        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.101.15:3000/feed30");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jbuffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        //close graphite client
        graphite_finalize();

        /*reset 30 sec timestamp*/
        half_min_stamp = local_tv_sec;

    }

        /*5 min avg*/
    if (local_tv_sec >= five_min_stamp + 300)
    {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");


        jwOpen( jbuffer, jbuflen, JW_OBJECT, JW_COMPACT);

        for (unsigned int i = 0; i < aid; i++)
        {
            vnfo_array[i].vlan_five_min_pps = (vnfo_array[i].vlan_pkt_cnt - vnfo_array[i].vlan_five_min_pkt_last) / 300;
            vnfo_array[i].vlan_five_min_pkt_last = vnfo_array[i].vlan_pkt_cnt;

            //write json object
            sprintf(vbuffer, "%04d", vnfo_array[i].vlan_id);
            jwObj_int( vbuffer , vnfo_array[i].vlan_five_min_pps );
        }

        jwEnd();
        jerr= jwClose();

        //post jason to nodejs
        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.101.15:3000/feed300");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jbuffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        five_min_stamp = local_tv_sec;
    }
}
