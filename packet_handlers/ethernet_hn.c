#include "ethernet_hn.h"

void print_ipv6(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    time_t cas = hdr->ts.tv_sec;
    struct tm *ptm = localtime(&cas);
};

void print_ipv4(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    time_t cas = hdr->ts.tv_sec;
    struct tm *ptm = localtime(&cas);
};

void print_arp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    time_t cas = hdr->ts.tv_sec;
    struct tm *ptm = localtime(&cas);
};

void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    time_t cas = hdr->ts.tv_sec;
    struct tm *ptm = localtime(&cas);

    // Print protocol
    struct ether_header* eptr;
    eptr = (struct ether_header *)pkt;
    char* text_prot;

    switch(ntohs(eptr->ether_type)) {
        case ETHERTYPE_ARP:
            text_prot = "ARP";
            print_arp(args, hdr, pkt);
            break;
        
        case ETHERTYPE_IP:
            text_prot = "IP";
            print_ipv4(args, hdr, pkt);
            break;

        case ETHERTYPE_IPV6:
            text_prot = "IPV6";
            print_ipv6(args, hdr, pkt);
            break;
    }

    struct ether_header* eth_head;
    eth_head = (struct ether_header*)pkt;
    char* src = ether_ntoa((struct ether_addr*)eth_head->ether_shost);
    char* dest = ether_ntoa((struct ether_addr*)eth_head->ether_dhost);

    fprintf(stdout, "[%02d:%02d:%02d] %s | len %d, size %d %s -> %s%s", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, text_prot, hdr->len, hdr->caplen, src, dest, __NEWLINE__);
}