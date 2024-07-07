//
// Created by shubhangam on 9/3/24.
//

#ifndef IDS_LOGGER_H
#define IDS_LOGGER_H

#include <string>
#include "../utils/iohelper.h"

/**Class to Map data for logging/displaying infomation
 * on console (if applicable)
 * Contains only basic info of a packet
 * */
class ConsoleLog  {
    long int inter_arrival_time;
    int packet_Length;
    std::string src_mac, dst_mac, src_ip, dst_ip,protocol;

public:
    [[nodiscard]] long getInterArrivalTime() const {
        return inter_arrival_time;
    }

    void setInterArrivalTime(long interArrivalTime) {
        inter_arrival_time = interArrivalTime;
    }

    [[nodiscard]] int getPacketLength() const {
        return packet_Length;
    }

    void setPacketLength(int packetLength) {
        packet_Length = packetLength;
    }

    [[nodiscard]] const std::string &getSrcMac() const {
        return src_mac;
    }

    void setSrcMac(const std::string &srcMac) {
        src_mac = srcMac;
    }

    [[nodiscard]] const std::string &getDstMac() const {
        return dst_mac;
    }

    void setDstMac(const std::string &dstMac) {
        dst_mac = dstMac;
    }

    [[nodiscard]] const std::string &getSrcIp() const {
        return src_ip;
    }

    void setSrcIp(const std::string &srcIp) {
        src_ip = srcIp;
    }

    [[nodiscard]] const std::string &getDstIp() const {
        return dst_ip;
    }

    void setDstIp(const std::string &dstIp) {
        dst_ip = dstIp;
    }

    [[nodiscard]] const std::string &getAProtocol() const {
        return protocol;
    }

    void setAProtocol(const std::string &aProtocol) {
        protocol = aProtocol;
    }
};

/**Class to Map data for logging info to CSV file
 *
 * Contains all required info. of a packet.
 * */
 class FileLog {
     PacketData packet;


 };
#endif //IDS_LOGGER_H
