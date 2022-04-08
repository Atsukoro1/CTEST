#include "ethernet_hn.h"

void print_data(const char* buffer, int size) {
    fprintf(stdout, "%s" ,__NEWLINE__);
    for(size_t i = 0; i != size; i++) {
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

    print_data(pkt, 5);
};

void print_arp(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    struct arphdr* arp_header = (struct arphdr*)pkt;
    struct arpreq* arp_request = (struct arpreq*)pkt;

    char* flags = (char*)malloc(sizeof(char) * 300);

    char arp_flags_values[7] = {
        ATF_COM,
        ATF_PERM,
        ATF_PUBL,
        ATF_USETRAILERS,
        ATF_NETMASK,
        ATF_DONTPUB,
        ATF_MAGIC
    };

    char* arp_flag_descs[7] = {
        "Completed entry (ha valid)",
        "Permanent entry",
        "Publish entry",
        "Has requested trailers",
        "Want to use a netmask (only for proxy entries)",
        "Don't answer this addresses",
        "Automatically added entry"
    };

    for(size_t i = 0; i != (sizeof(arp_flags_values) / sizeof(arp_flags_values[0])); i++) {
        if(arp_flags_values[i] & arp_request->arp_flags) {
            strcat(flags, "\r\r\n     | ");
            strcat(flags, arp_flag_descs[i]);
        }
    };

    fprintf(stdout, "   | Header %s%s", "ARP", __NEWLINE__);
    fprintf(stdout, "   | FLAGS%s%s", flags, __NEWLINE__);
    fprintf(stdout, "   | Hardware addr length %d%s", arp_header->ar_hln, __NEWLINE__);

    free(flags);
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
            // print_ip(args, hdr, pkt);
            break;  
        
        case 0x86DD:
            // IPV6
            // print_ip(args, hdr, pkt);
            break;

        case 0x01:
            // ICMP / Not implemented
            break;

        case 0x809B:
            // Appletalk (Ethertalk) / Not implemented for now
            break;

        case 0x80F3:
            // Appletalk Address Resolution protocol (AARP) / Not implemented for now
            break;

        case 0x8100:
            // VLAN & IEEE 802.1Q / Not implemented for now
            break;

        case 0x8137:
            // IPX / Not implemented for now
            break;

        case 0x8204:
            // QNX Qnet / Not implemented for now
            break;

        case 0x8808:
            // Ethernet flow control / Not implemented for now
            break;

        case 0x8819:
            // CobraNet / Not implemented for now
            break;

        case 0x8847:
            // MLPS Multicast / Not implemented for now
            break;

        case 0x8848:
            // MLPS Multicast / Not implemented for now
            break;

        case 0x8863:
            // PPPoE Discovery stage / Not implemented for now
            break;

        case 0x8870:
            // Jumbo frames / Not implemented for now
            break;

        case 0x887B:
            // HomePlug 1.0 MME / Not implemented for now
            break;

        case 0x888E:
            // EAP over LAN (IEEE 802.1X) / Not implemented for now
            break;

        case 0x8892:
            // PROFINET Protocol / Not implemented for now
            break;

        case 0x889A:
            // HYPERSCSI (SCSI over Ethernet) / Not implemented for now
            break;

        case 0x99A2:
            // ATA over Ethernet / Not implemented for now
            break;

        case 0x88A4:
            // EtherCAT Protocol / Not implemented for now
            break;

        case 0x88A8:
            // Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq / Not implemented for now
            break;

        case 0x88AB:
            // Ethernet Powerlink / Not implemented for now
            break;

        case 0x88CC:
            // Link Layer Discovery Protocol / Not implemented for now
            break;

        case 0x88CD:
            // SERCOS III / Not implemented for now
            break;

        case 0x88E1:
            // Homeplug AV MME / Not implemented for now
            break;

        case 0x88E3:
            // Media Redundancy Protocol (IEC62439-2) / Not implemented for now
            break;

        case 0x88E5:
            // MAC Security (IEEE 802.1AE) / Not implemented for now
            break;

        case 0x88F7:
            // Precision Time Protocol (PTP over Ethernet) (IEEE 1588) / Not implemented for now
            break;

        case 0x8902:
            // IEEE 802.1ag Connectivity Fault Management (CFM) / Not implemented for now
            break;

        case 0x8906:
            // Fibre Channel over Ethernet (FCoE) / Not implemented for now
            break;

        case 0x8914:
            // FCoE Initialization Protocol / Not implemented for now
            break;

        case 0x8915:
            // RDMA over Converged Ethernet / Not implemented for now
            break;

        case 0x892F:
            // High-availability Seamless Redundancy (HSR) / Not implemented for now
            break;

        case 0x9000:
            // Ethernet Configuration Testing Protocol / Not implemented for now
            break;

        case 0x9100:
            // Q-in-Q / Not implemented for now
            break;

        case 0xCAFE:
            // Veritas Low Latency Transport / Not implemented for now
            break;
    }
}