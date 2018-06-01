#ifndef HANDLER_H_INCLUDED
#define HANDLER_H_INCLUDED

void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

#endif // HANDLER_H_INCLUDED
