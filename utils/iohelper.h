//
// Created by shubhangam on 31/8/23.
//

#ifndef IDS_IOHELPER_H
#define IDS_IOHELPER_H

#endif //IDS_IOHELPER_H

#include <iostream>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstring>
#include <fstream>

/** Assists in choice selection
 * @arg
 */
char *choiceSelection(std::vector<char *> choices) {
    int choice;
    int choiceCounter = 0;
    auto itr = choices.begin();
    std::cout << "Please select any one of the following : " << std::endl;
    while (itr < choices.end()) {
        choiceCounter++;
        std::cout << choiceCounter << " " << *itr;
        itr++;
    }
    while (true) {
        std::cout << "Enter your selection :" << std::endl;
        std::cin >> choice;
        if (choice >= choiceCounter && choice > 0) {
            break;
        } else {
            std::cout << "Invalid Selection." << std::endl;
        }
    }
    return choices[choice];
}

/**Get system Date
 * */
char *getCurrentTime() {
    auto timeNow =
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char *formatted_date = ctime(&timeNow);
    formatted_date[strlen(formatted_date) - 1] = '\0';
    return formatted_date;
}

/** Logs Message on console
*/
void log(char *msg) {
    std::cout << getCurrentTime() << " : " << msg << std::endl;
}

void log(const std::string &msg) {
    std::cout << getCurrentTime() << " : " << msg << std::endl;
}




class PacketData {
    time_t seconds_value;
    suseconds_t microseconds_value;
    u_int16_t etherType; /*Typ of frame captured from wire*/
    u_int32_t length; /* Length of packet */
    u_int64_t src_mac; /* Source MAC address */
    u_int64_t dst_mac; /* Destination MAC address */
    u_int32_t src_ip; /* Source IP address */
    u_int32_t dst_ip; /* Destination IP Address*/
    float protocol; /*Type of protocol [0.1 = ARP, 0.2 = TCP, 0.3 = UDP]*/

public:

    PacketData() = default;

    [[nodiscard]] time_t getSecondsValue() const {
        return seconds_value;
    }

    void setSecondsValue(time_t secondsValue) {
        seconds_value = secondsValue;
    }

    [[nodiscard]] suseconds_t getMicrosecondsValue() const {
        return microseconds_value;
    }

    void setMicrosecondsValue(suseconds_t microsecondsValue) {
        microseconds_value = microsecondsValue;
    }

    [[nodiscard]] u_int32_t getLength() const {
        return length;
    }

    void setLength(u_int32_t length) {
        PacketData::length = length;
    }

    [[nodiscard]] u_int64_t getSrcMac() const {
        return src_mac;
    }

    [[nodiscard]] u_int64_t getDstMac() const {
        return dst_mac;
    }

    void setSrcMac(u_int64_t srcMac) {
        src_mac = srcMac;
    }

    void setDstMac(u_int64_t dstMac) {
        dst_mac = dstMac;
    }

    [[nodiscard]] u_int32_t getSrcIp() const {
        return src_ip;
    }

    void setSrcIp(u_int32_t srcIp) {
        src_ip = srcIp;
    }

    [[nodiscard]] u_int32_t getDstIp() const {
        return dst_ip;
    }

    void setDstIp(u_int32_t dstIp) {
        dst_ip = dstIp;
    }

    [[nodiscard]] float getAProtocol() const {
        return protocol;
    }

    void setAProtocol(float aProtocol) {
        protocol = aProtocol;
    }

};

/**Records data to .csv file
 */
void logToFile(PacketData packetData ) {
    std::fstream filePointer;

    //create or open the file
    filePointer.open("data.csv", std::ios::out | std::ios::app);
    filePointer << packetData.getSecondsValue()<<","
            << packetData.getLength()<<","
            << packetData.getSrcMac()<<","
            << packetData.getDstMac()<<","
            << packetData.getSrcIp()<<","
            << packetData.getDstIp()<<","
            << packetData.getAProtocol()<<"\n";
    filePointer.close();
}

/**Cast unit8_t[4] to unit32_t*
 * */
 u_int32_t castTo32bit(const uint8_t ip[4]){
    u_int32_t i32 = ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
    return i32;
 }

/**Cast u_char[6] to uint64_t
 * */
 u_int64_t castMACTo64bit(const u_char address[8]){
    uint64_t result = 0;

    // Assuming little-endian byte order (LSB is at bytes[0])
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t) address[i] << (i * 8));
    }
    return result;
 }