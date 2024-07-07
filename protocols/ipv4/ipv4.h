//
// Created by shubhangam on 10/3/24.
//

#ifndef IDS_IPV4_H
#define IDS_IPV4_H

#include "../protocol.h"
#include "packet_headers.h"

class ipv4 : public Protocol {
public :
    ipv4() = default;
    const struct ip_hdr *header;
};

#endif //IDS_IPV4_H
