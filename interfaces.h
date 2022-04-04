#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef INTERFACES_H
#define INTERFACES_H

#define __NEWLINE__ "\r\r\n"
#define __SEPARATOR__ "------------------------"

/*
    Print all flags in human readable string 
    instead of hexadecimal number
*/
char* get_interface_flags(bpf_u_int32* decimal_flags);

/*
    Print available information about network interface
    This recursive function can be called again
    if there is more than one interface present
*/
void print_interface(pcap_if_t* device);

/*
    Let users select the interface they want to capture packets on
    Selected interface should be string, not position in list!!
*/
char* get_selected_interface();

/*
    Will convert decimal data-link header value to human-readable 
    string that will contain linklayer type
*/
char* get_datalink(pcap_t* device);

#endif