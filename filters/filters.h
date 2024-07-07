//
// Created by shubhangam on 13/9/23.
//
#include <pcap.h>
#include <iostream>

#ifndef IDS_FILTERS_H
#define IDS_FILTERS_H

#endif //IDS_FILTERS_H

/**
 * Function to assist in compilation  & application of  BPF (Berkeley Packet Filter)
 * @see https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters
 * */
void compile_and_apply_filter(
        const char *_filter,                              /* Filter in Human Readable format*/
        pcap_t *_handle,                      /*Pcap handler to handle open interfaces*/
        bpf_u_int32 _netmask,                     /*Netmask of the network segment*/
        int _optimize                            /*Default value for optimization in 0*/
) {
    struct bpf_program programAddress{};      /* To store the compiled __filter in Machine code*/
    log("Compiling filters....");
    int compilation_status = pcap_compile(_handle, &programAddress, _filter, _optimize, _netmask);
    if (compilation_status == -1) {
        std::cout << "Error Occurred [BPF Compilation] : " << pcap_geterr(_handle) << std::endl;
        exit(1);
    } else {
        log("Filters compiled successfully.");
        log("Setting up filters....");
        int filter_apply_status = pcap_setfilter(_handle, &programAddress);
        if (filter_apply_status == -1) {
            std::cout << "Error Occurred [Set Filter]: " << pcap_geterr(_handle) << std::endl;
            exit(1);
        } else {
            log("Filters applied successfully.");
            pcap_freecode(&programAddress);
        }
    }
}