//
// Created by shubhangam on 10/3/24.
//

#ifndef IDS_TCP_H
#define IDS_TCP_H

#include "../protocol.h"
#include "packet_headers.h"

class tcp : public Protocol {
public :
    tcp() = default;
    const struct tcp_hdr *header{};
};
#endif //IDS_TCP_H
