#include "capture.h"
#include "interfaces.h"
#include "./packet_handlers/ethernet_hn.h"

void setup_capture(char* device) {
    char* errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* created = pcap_create(device, *errbuf);

    int timeout_success = pcap_set_timeout(created, 150);

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