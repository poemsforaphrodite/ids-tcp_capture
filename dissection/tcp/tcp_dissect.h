//
// Created by shubhangamg on 4/3/24.
//

#ifndef IDS_TCP_DISSECT_H
#define IDS_TCP_DISSECT_H
#include "packet_headers.h"
#include "process_packets.h"

u_int connections_count;

class TCP {
public :
    /**This method parses TCP header and reads flags to get data of a TCP connection
     * @arg packet : raw packet of u_char type parsed form pay load of IP Layer
     * */
    void dissect(u_char *packet) {
        struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + SIZE_ETHERNET + size_ip);


    }
};
#endif //IDS_TCP_DISSECT_H
