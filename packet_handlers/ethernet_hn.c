#include "ethernet_hn.h"

void print_data(const char* buffer, int size) {
    fprintf(stdout, "%s" ,__NEWLINE__);
    for(size_t i = 0; i != 10; i++) {
        for (size_t a = 0; a < 10; a++) {
            if(buffer[i * a] < 0) {
                fprintf(stdout, " FF");
            } else {
                fprintf(stdout, " %02X", (unsigned int)buffer[i * a]);
            }
        }

        fprintf(stdout, "%s", "         ");

        for (size_t a = 0; a < 10; a++) {
            if(buffer[i * a] > 33 && buffer[i * a] < 127) {
                fprintf(stdout, " %c", (unsigned char)buffer[i * a]);
            } else {
                fprintf(stdout, " .");
            }
        }

        fprintf(stdout, "%s", __NEWLINE__);
    }
}

void print_ip_uint_to_string(unsigned int raw_ip, char* text) {
    unsigned char ip_addr[4];
    ip_addr[0] = raw_ip & 0xFF;
    ip_addr[1] = (raw_ip >> 8) & 0xFF;
    ip_addr[2] = (raw_ip >> 16) & 0xFF;
    ip_addr[3] = (raw_ip >> 24) & 0xFF;
    fprintf(stdout, "%s %d:%d:%d:%d%s", text, ip_addr[3], ip_addr[2], ip_addr[1], ip_addr[0], __NEWLINE__);
}

void print_ip(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    struct iphdr *iph = (struct iphdr *)pkt;

    fprintf(stdout, "   | Header %s%s", "IP", __NEWLINE__);
    fprintf(stdout, "   | Version %d%s", iph->version, __NEWLINE__);
    fprintf(stdout, "   | TTL %d%s", iph->ttl, __NEWLINE__);
    fprintf(stdout, "   | PROTOCOL %d%s", iph->protocol, __NEWLINE__);
    fprintf(stdout, "   | TOS %d%s", iph->tos, __NEWLINE__);
    fprintf(stdout, "   | FRAG OFF %d%s", iph->frag_off, __NEWLINE__);
    fprintf(stdout, "   | CHECK %d%s", iph->check, __NEWLINE__);
    print_ip_uint_to_string(iph->saddr, "   | SRC");
    print_ip_uint_to_string(iph->daddr, "   | DEST");

    print_data(pkt, hdr->len);
};

void print_arp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
};

void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    time_t cas = hdr->ts.tv_sec;
    struct tm *ptm = localtime(&cas);

    // Print protocol
    struct ether_header* eptr;
    eptr = (struct ether_header *)pkt;
    char* text_prot;

    struct ether_header* eth_head;
    eth_head = (struct ether_header*)pkt;
    char* src = ether_ntoa((struct ether_addr*)eth_head->ether_shost);
    char* dest = ether_ntoa((struct ether_addr*)eth_head->ether_dhost);

    fprintf(stdout, "%s[%02d:%02d:%02d] | len %d, size %d %s -> %s%s", __NEWLINE__, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, hdr->len, hdr->caplen, src, dest, __NEWLINE__);

    switch(ntohs(eptr->ether_type)) {
        case 0x0806:
            // ARP
            print_arp(args, hdr, pkt);
            break;

        case 0x0800:
            // IPV4
            print_ip(args, hdr, pkt);
            break;  
        
        case 0x86DD:
            // IPV6
            print_ip(args, hdr, pkt);
            break;
    }
}