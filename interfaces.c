#include "interfaces.h"

char* get_datalink(pcap_t* device) {
    int data_link_type = pcap_datalink(device);

    int linktype_nums[109] = {
        0, 1, 3, 6, 7, 8, 9, 10, 50, 51,
        100, 101, 104, 105, 107, 108, 113, 114, 117, 119,
        122, 123, 127, 129, 138, 139, 140, 141, 142, 143,
        144, 163, 165, 166, 169, 170, 171, 177, 182, 187,
        189, 192, 195, 196, 197, 201, 202, 203, 204, 205,
        206, 207, 209, 210, 212, 215, 220, 224, 225, 226,
        237, 239, 240, 241, 242, 243, 244, 245, 247, 248,
        249, 250, 251, 252, 253, 254, 255, 256, 257, 258,
        259, 260, 261, 262, 263, 264, 266, 268, 270, 271,
        272, 273, 274, 275, 276, 278, 279, 280, 281, 282,
        283, 284, 285, 286, 287, 288, 289, 290, 292
    };

    char* linktype_names[109] = {
        "NULL", "ETHERNET", "AX25", "IEEE802_5", "ARCNET_BSD",
        "SLIP", "PPP", "FDDI", "PPP_HDLC", "PPP_ETHER",
        "ATM_RFC1483", "RAW", "C_HDLC", "IEEE802_11", "FRELAY",
        "LOOP", "LINUX_SLL", "LTALK", "PFLOG", "IEEE802_11_PRISM",
        "IP_OVER_FC", "SUNATM", "IEEE802_11_RADIOTAP", "ARCNET_LINUX", "APPLE_IP_OVER_IEEE1394",
        "MTP2_WITH_PHDR", "MTP2", "MTP3", "SCCP", "DOCSIS",
        "LINUX_IRDA", "IEEE802_11_AVS", "BACNET_MS_TP", "PPP_PPPD",
        "GPRS_LLC", "GPF_T", "GPF_F", "LINUX_LAPD", "MFR",
        "BLUETOOTH_HCI_H4", "USB_LINUX", "PPI", "IEEE802_15_4_WITHFCS", "SITA",
        "ERF", "BLUETOOTH_HCI_H4_WITH_PHDR", "AX25_KISS", "LAPD", "PPP_WITH_DIR",
        "HDLC_WITH_DIR", "FRELAY_WITH_DIR", "LAPB_WITH_DIR", "IPMB_LINUX", "FLEXRAY",
        "LIN", "IEEE802_15_4_NONASK_PHY", "USB_LINUX_MMAPPED", "FC_2", "FC_2_WITH_FRAME_DELIMS",
        "IPNET", "CAN_SOCKETCAN", "IPV4", "IPV6", "IEEE802_15_4_NOFCS",
        "DBUS", "DVB_CI", "MUX27010", "STANAG_5066_D_PDU", "NFLOG",
        "NETANALYZER", "NETANALYZER_TRANSPARENT", "IPOIB", "MPEG_2_TS", "NG40",
        "NFC_LLCP", "INFINIBAND", "SCTP", "USBPCAP", "RTAC_SERIAL",
        "BLUETOOTH_LE_LL", "NETLINK", "BLUETOOTH_LINUX_MONITOR", "BLUETOOTH_BREDR_BB", "BLUETOOTH_LE_LL_WITH_PHDR",
        "PROFIBUS_DL", "PKTAP", "EPON", "IPMI_HPM_2", "ZWAVE_R1_R2",
        "ZWAVE_R3", "WATTSTOPPER_DLM", "ISO_14443", "RDS", "USB_DARWIN",
        "SDLC", "LORATAP", "VSOCK", "NORDIC_BLE", "DOCSIS31_XRA31",
        "ETHERNET_MPACKET", "DISPLAYPORT_AUX", "LINUX_SLL2", "OPENVIZSLA", "EBHSCR",
        "VPP_DISPATCH", "DSA_TAG_BRCM", "DSA_TAG_BRCM_PREPEND", "IEEE802_15_4_TAP", "DSA_TAG_DSA"
    };

    int pos = -1;

    for (size_t i = 0; i != (sizeof(linktype_nums) / sizeof(linktype_nums[0])); i++)
    {
        if(linktype_nums[i] == data_link_type) {
            pos = i;
            break;
        };
    };
    
    return linktype_names[pos];
};

char* get_interface_flags(bpf_u_int32* decimal_flags) {
    char* flag_string = (char*)malloc(sizeof(char) * 130);
    strcpy(flag_string, "\0");

    const int flag_names[8] = {
        PCAP_IF_LOOPBACK, 
        PCAP_IF_UP, 
        PCAP_IF_RUNNING, 
        PCAP_IF_WIRELESS,
        PCAP_IF_CONNECTION_STATUS_UNKNOWN,
        PCAP_IF_CONNECTION_STATUS_CONNECTED,
        PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
        PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE
    };

    const char* flag_values[8] = {
        "LOOPBACK",
        "UP",
        "RUNNING",
        "WIRELESS",
        "UNKNOWN",
        "CONNECTED",
        "DISCONNECTED",
        "NOT_APPLICABLE"
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
    char* device_desc = device->description == NULL ? "No description provided" : device->description;
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