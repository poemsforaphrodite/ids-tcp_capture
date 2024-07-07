//
// Created by shubhangam on 10/3/24.
//

#ifndef IDS_UDP_H
#define IDS_UDP_H

#include "../protocol.h"

class udp : public Protocol {
public :
    udp() = default;
    const struct udp_hdr * header;
};
#endif //IDS_UDP_H
