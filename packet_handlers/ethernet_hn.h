#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <time.h>

#ifndef ETHERNET_HN_H
#define ETHERNET_HN_H

#define __NEWLINE__ "\r\r\n"
#define __SEPARATOR__ "------------------------"

void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt);

#endif