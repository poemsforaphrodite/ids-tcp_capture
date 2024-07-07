// Tutorials : http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-10-SECT-2.html
// Tutorials : https://www.tcpdump.org/pcap.html
// Tutorials : https://www.cprogramming.com/debugging/segfaults.html

#include <iostream>
#include <pcap.h>
#include "utils/iohelper.h"
#include "filters/filters.h"
#include "packets/process_packets.h"


char * getEthernetInterface(pcap_if_t *devices) {
    int interface_choice;
    std::cout<<"Choose Interface form the above list (e.g enter 1 for first, 2 for second):"<<std::endl;
    std::cin>>interface_choice;

    for(int i = 1; i < interface_choice; i++){
        devices = devices->next;
    }
    return devices->name;
}


int main() {
    pcap_if_t *interfaces;
    char err_buffer[PCAP_ERRBUF_SIZE];

    log("Detecting interfaces....");
    int detected_interfaces = pcap_findalldevs(&interfaces, err_buffer);
    if (detected_interfaces < 0) {
        std::cout << "Error : " << err_buffer;
        exit(1);
    } else {
        pcap_if *devices = (interfaces);
        int interface_counter = 1;
        while (devices != nullptr) {
            std::cout << interface_counter<< ". "<<devices->name << std::endl;
            devices = devices->next;
            interface_counter++;
        }
    }

    char *eth_interface = getEthernetInterface((interfaces));
    pcap_t *handle = pcap_open_live(eth_interface, 1500, 1, 0, err_buffer);
    if (handle == nullptr) {
        std::cout << "Error Occurred in accessing interface : " << err_buffer << std::endl;
        exit(1);
    }
    //Check if interface is ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cout << "This program is for Ethernet only." << std::endl;
        exit(1);
    }
    //Get IP details from interface
    bpf_u_int32 ip_address;
    bpf_u_int32 netmask;
    if (pcap_lookupnet(eth_interface, &ip_address, &netmask, err_buffer) == -1) {
        std::cout << "Error occurred in IP resolution : " << err_buffer << std::endl;
        exit(1);
    } else {
        char *ip_add;
        struct in_addr addr{};
        addr.s_addr = ip_address;
        ip_add = inet_ntoa(addr);
        std::cout << "IP Address of " << eth_interface << " is : " << ip_add << std::endl;
    }
    //Compile ARP filter & Set the compiled filter to the handle (opened interface)
    const char *filter = "not host 10.23.0.95 and not host 10.23.0.27";
    compile_and_apply_filter(filter,handle,netmask,0);
    //Read the captured packets
    int flag;
    u_char* user;
    if((flag = pcap_loop(handle, -1 ,process_packet_, user) < 0)){
        if(flag == -1){
            std::cout << "Error Occurred : "<<pcap_geterr(handle)<<std::endl;
            exit(1);
        }
    }
    pcap_close(handle);
    return 0;
}

