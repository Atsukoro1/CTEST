#include "capture.h"
#include "interfaces.h"

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
            break;
        
        case ETHERTYPE_IP:
            text_prot = "IP";
            break;

        case ETHERTYPE_IPV6:
            text_prot = "IPV6";
            break;

        case ETHERTYPE_REVARP:
            text_prot = "RARP";
            break;

        case ETHERTYPE_LOOPBACK:
            text_prot = "LOOPBACK";
            break;

        case ETHERTYPE_VLAN:
            text_prot = "VLAN";
            break;

        case ETHERTYPE_AARP:
            text_prot = "AARP";
            break;

        case ETHERTYPE_NTRAILER:
            text_prot = "NTRAILER";
            break;
    }

    // Source and destination MAC addresses
    struct ether_header* eth_head;
    eth_head = (struct ether_header*)pkt;
    char* src = ether_ntoa((struct ether_addr*)eth_head->ether_shost);
    char* dest = ether_ntoa((struct ether_addr*)eth_head->ether_dhost);

    fprintf(stdout, "[%02d:%02d:%02d] %s | len %d, size %d %s -> %s%s", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, text_prot, hdr->len, hdr->caplen, src, dest, __NEWLINE__);

    for (size_t i = 0; i < hdr->len; i++)
    {
        fprintf(stdout, "%c", pkt[i]);
    }

    fprintf(stdout, "%s%s", __NEWLINE__, __NEWLINE__);
    
}

void setup_capture(char* device) {
    char* errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* created = pcap_create(device, *errbuf);

    int timeout_success = pcap_set_timeout(created, 100);

    int buf_size_success = pcap_set_buffer_size(created, 10);

    pcap_set_promisc(created, 1);

    if(timeout_success == PCAP_ERROR_ACTIVATED || buf_size_success == PCAP_ERROR_ACTIVATED) {
        fprintf(stdin, "The device you're trying to set timeout or buffer size on is already activated and can't be modified");
    }

    if(created == NULL) {
        fprintf(stderr, "%s%s", *errbuf, __NEWLINE__);
        return exit(EXIT_FAILURE);
    }

    int activation_status = pcap_activate(created);

    if(activation_status == PCAP_ERROR || activation_status != 0) {
        fprintf(stderr, "%s", pcap_geterr(created));
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "%sYou are now listening to %s (%s)!%s", __NEWLINE__, device, get_datalink(created), __NEWLINE__);

    int loop_status = pcap_loop(created, -1, captured_packet, NULL);

    switch (loop_status) 
    {
        case PCAP_ERROR_BREAK:
            fprintf(stderr, "Loop was finished beacause of breakloop that was called.");
            break;
    
        case PCAP_ERROR_NOT_ACTIVATED:
            fprintf(stderr, "Device wasn't activated before it started capturing.");
            break;

        case 0:
            fprintf(stderr, "Loop was terminated due to exhaustion of count");
            break;

        default:
            fprintf(stderr, "Some error happened while trying to loop through packets -> %s", pcap_geterr(created));
            break;
    }

    pcap_close(created);
    exit(0);
}