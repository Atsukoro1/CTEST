#include "interfaces.h"

char* get_interface_flags(bpf_u_int32* decimal_flags) {
    char* flag_string = (char*)malloc(sizeof(char) * 30);
    strcpy(flag_string, "\0");

    const int flag_names[4] = {
        PCAP_IF_LOOPBACK, 
        PCAP_IF_UP, 
        PCAP_IF_RUNNING, 
        PCAP_IF_WIRELESS
    };

    const char* flag_values[4] = {
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

void print_interface(pcap_if_t* device) {
    bpf_u_int32* flags = &device->flags;
    char* device_name = device->name;
    char* device_desc = device->description;
    char* flags_string = get_interface_flags(flags);

    pcap_addr_t* addr = device->addresses;

    if(strlen(flags_string) != 0) {
        fprintf(stdout, "%s: FLAGS(%lu)<%s>%s", device_name, strlen(flags_string), flags_string, __NEWLINE__);    
        fprintf(stdout, "%s%s", device_desc, __NEWLINE__);
        fprintf(stdout, "%s%s", __SEPARATOR__, __NEWLINE__);
    }

    if(device[0].next != NULL) print_interface(device->next);
    
    free(flags_string);
}

char* get_selected_interface() {
    char* selected_interface = (char*)malloc(sizeof(char) * 20);
    char* device_name;
    char* ip_addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    int devices_succefully_returned = pcap_findalldevs(&alldevs, errbuf);
    if(devices_succefully_returned == PCAP_ERROR) {
        printf("%s", errbuf);
        return '\0';
    }

    print_interface(alldevs);

    fprintf(stdout, "Name of the network interface to use: ");
    fgets(selected_interface, 20, stdin);

    strtok(selected_interface, "\0");
    strtok(selected_interface, "\n");

    return selected_interface;
}