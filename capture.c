#include "capture.h"

void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    fprintf(stdout, "%s", pkt);
}

void setup_capture(char* device) {
    char* errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* created = pcap_create("any", *errbuf);

    int timeout_success = pcap_set_timeout(created, 0);

    int buf_size_success = pcap_set_buffer_size(created, 10);

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

    fprintf(stdout, "Interface activated!%s", __NEWLINE__);

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