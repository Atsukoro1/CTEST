/* 
    Run this tool as ROOT (without root it may show less interfaces)!
    Please ensure that all required libraries are installed,
    to make sure everything will run correctly.

    Compile and run it using GCC
    gcc main.c -o output -L/usr/include -lpcap && ./output
*/
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define __NEWLINE__ "\r\r\n"
#define __SEPARATOR__ "------------------------"

/*
    Print all flags in human readable string 
    instead of hexadecimal number
*/
char* get_interface_flags(bpf_u_int32* decimal_flags) {
    char* flag_string = (char*)malloc(sizeof(char) * 30);
    strcpy(flag_string, "\0");

    const int flag_names[9] = {
        PCAP_IF_LOOPBACK, 
        PCAP_IF_UP, 
        PCAP_IF_RUNNING, 
        PCAP_IF_WIRELESS
    };

    const char* flag_values[9] = {
        "LOOPBACK",
        "UP",
        "RUNNING",
        "WIRELESS"
    };

    for (size_t i = 0; i < (sizeof(flag_names) / sizeof(flag_names[0])); i++)
    {
        if(flag_names[i] & *decimal_flags) {
            if(strlen(flag_string) != 0) strcat(flag_string, ", ");
            strcat(flag_string, flag_values[i]);
        }
    }
    
    return flag_string;
}

/*
    Print available information about network interface
    This recursive function can be called again
    if there is more than one interface present
*/
void print_interface(pcap_if_t* device) {
    // Device parameters
    bpf_u_int32* flags = &device->flags;
    pcap_addr_t* addr = device->addresses;
    char* device_name = device->name;
    char* flags_string = get_interface_flags(flags);  

    printf("%s: FLAGS(%lu)<%s>%s", device_name, strlen(flags_string), flags_string, __NEWLINE__);    
    printf("%s%s", __SEPARATOR__, __NEWLINE__);

    // Check if there is another device to print, if so call the recursive function again
    if(device[0].next != NULL) print_interface(device->next);
    
    free(flags_string);
}

// Let user select the network interface that will capture packets
char* get_selected_interface() {
    char* selected_interface = (char*)malloc(sizeof(char) * 20);
    char* device_name;
    char* ip_addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    // Get all available network interfaces, returns PCAP_ERROR on failure or 0 on success
    int devices_succefully_returned = pcap_findalldevs(&alldevs, errbuf);

    // If there was an error while fetching interfaces, return empty char
    if(devices_succefully_returned == PCAP_ERROR) {
        printf("%s", errbuf);
        return '\0';
    }

    print_interface(alldevs);

    printf("Name of the network interface to use: ");
    fgets(selected_interface, 20, stdin);

    return selected_interface;
}

void captured_packet(u_char *useless, const struct pcap_pkthdr* hdr, const u_char*packet) {
    printf("CCCC");
}

void capture(char* device) {
    char* errbuf[PCAP_ERRBUF_SIZE];

    /*
        Will create a packet capture handle
        Returns NULL if handle can't be created, in this case
        we'll print out the error buffer and exit the program with 1 status code
    */
    pcap_t* created = pcap_create("eth0", *errbuf);

    if(created == NULL) {
        printf("%s%s", *errbuf, __NEWLINE__);
        return exit(EXIT_FAILURE);
    };

    int activation_status = pcap_activate(created);

    if(activation_status == PCAP_ERROR || activation_status != 0) {
        printf("%s", pcap_geterr(created));
        exit(EXIT_FAILURE);
    }

    /*
        Interface was activated so start capturing incoming packets
        capture_packet will handle incoming packets.
        We'll capture infinite amount of packets unless user provides a count
    */
    printf("Interface activated!%s", __NEWLINE__);

    int loop_status = pcap_loop(created, 419829675, captured_packet, NULL);

    switch (loop_status) 
    {
    case PCAP_ERROR_BREAK:
        printf("Loop was finished beacause of breakloop that was called.");
        break;
    
    case PCAP_ERROR_NOT_ACTIVATED:
        printf("Device wasn't activated before it started capturing.");
        break;

    case 0:
        printf("Loop was terminated due to exhaustion of count");
        break;

    default:
        printf("Some error happened while trying to loop through packets -> %s", pcap_geterr(created));
        break;
    }

    // Program was successfully closed, exit..
    pcap_close(created);
    exit(0);
}

int main(int argc, char **argv) {
    if(getuid() != 0) {
        printf("Please make sure to run this tool as root!%s", __NEWLINE__);
        return 1;
    }

    char* selected = get_selected_interface();
    capture(selected);
    free(selected);
    return 0;
}