#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <time.h>

#ifndef CAPTURE_H
#define CAPTURE_H

#define __NEWLINE__ "\r\r\n"
#define __SEPARATOR__ "------------------------"

void setup_capture(char* device);
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt);

#endif