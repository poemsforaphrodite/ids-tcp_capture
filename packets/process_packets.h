//
// Created by shubhangam on 13/9/23.
//
#include <iostream>
#include <pcap.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include "packet_headers.h"

#ifndef IDS_PROCESS_PACKETS_H
#define IDS_PROCESS_PACKETS_H
#define SIZE_ETHERNET 14

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

const struct eth_hdr *ethernet; /* The ethernet header */
const struct ip_hdr *ip; /* The IP header */
const struct tcp_hdr *tcp; /* The TCP header */
const struct udp_hdr *udp; /* The UDP Header*/
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;
PacketData packetData;
#endif //IDS_PROCESS_PACKETS_H

/* Callback to process a captured ARP packet
 ** */
void process_arp_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
    struct ether_arp *arp_packet; /* from if_eth.h */

    eth_header = (struct ether_header *) packet;
    arp_packet = (struct ether_arp *) (packet + ETH_HLEN);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)  /* if it is an ARP packet */
    {
        std::cout << getCurrentTime() << "->";
        printf("Source IP Address: %d.%d.%d.%d\t\t\t Destination IP Address: %d.%d.%d.%d\n",
               arp_packet->arp_spa[0],
               arp_packet->arp_spa[1],
               arp_packet->arp_spa[2],
               arp_packet->arp_spa[3],
               arp_packet->arp_tpa[0],
               arp_packet->arp_tpa[1],
               arp_packet->arp_tpa[2],
               arp_packet->arp_tpa[3]);
    } else {
        std::cout << "The packet captured is not of ARP type." << std::endl;
    }
}

/* Callback to process a captured TCP packet
 ** */
void process_tcp_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + 0X14 + 0x0E);
    std::cout << getCurrentTime() << "->" << "TCP Header info : Sequence : " << tcp_header->th_seq << "  Ack : "
              << tcp_header->th_ack << std::endl;

}

/* Callback to process every captured packet
 ** */
void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    ethernet = (struct eth_hdr *) (packet);
    ip = (struct ip_hdr *) (packet + SIZE_ETHERNET);
    if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        process_arp_packet(user, header, packet);
    } else {
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            std::cout << getCurrentTime() << "->";
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            std::cout << std::endl;

        } else {
            std::cout << getCurrentTime() << "->" << "Source IP : " << inet_ntoa(ip->ip_src) << "\t\t"
                      << "Destination IP : " << inet_ntoa(ip->ip_dst);
            std::cout << std::endl;
        }
        tcp = (struct tcp_hdr *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) {
            std::cout << getCurrentTime() << "->";
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            std::cout << std::endl;
        }
    }

}

void process_packet_(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {

    ////Data Collection for CSV
    packetData.setSecondsValue(header->ts.tv_sec);
    packetData.setLength(header->caplen);
    ////Data Collection for CSV

    ethernet = (struct eth_hdr *) (packet);
    std::cout << getCurrentTime();
    printf(" : Source MAC : %02X-%02X-%02X-%02X-%02X-%02X \t Destination MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
       ethernet->ether_shost[0],
       ethernet->ether_shost[1],
       ethernet->ether_shost[2],
       ethernet->ether_shost[3],
       ethernet->ether_shost[4],
       ethernet->ether_shost[5],
       ethernet->ether_dhost[0],
       ethernet->ether_dhost[1],
       ethernet->ether_dhost[2],
       ethernet->ether_dhost[3],
       ethernet->ether_dhost[4],
       ethernet->ether_dhost[5]);
    ////Data Collection for CSV
    u_char src_mac64[8];
    src_mac64[0] = 0x0;
    src_mac64[1] = 0x0;
    src_mac64[2] = ethernet->ether_shost[0];
    src_mac64[3] = ethernet->ether_shost[1];
    src_mac64[4] = ethernet->ether_shost[2];
    src_mac64[5] = ethernet->ether_shost[3];
    src_mac64[6] = ethernet->ether_shost[4];
    src_mac64[7] = ethernet->ether_shost[5];

    u_char dst_mac64[8];
    dst_mac64[0] = 0x0;
    dst_mac64[1] = 0x0;
    dst_mac64[2] = ethernet->ether_dhost[0];
    dst_mac64[3] = ethernet->ether_dhost[1];
    dst_mac64[4] = ethernet->ether_dhost[2];
    dst_mac64[5] = ethernet->ether_dhost[3];
    dst_mac64[6] = ethernet->ether_dhost[4];
    dst_mac64[7] = ethernet->ether_dhost[5];


    packetData.setSrcMac(castMACTo64bit(src_mac64));
    packetData.setDstMac(castMACTo64bit(dst_mac64));
    ////Data Collection for CSV

    if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_packet;
        arp_packet = (struct ether_arp *) (packet + ETH_HLEN);
        std::cout << "\t PACKET TYPE : ARP";
        printf(" Source IP Address: %d.%d.%d.%d\t\t Destination IP Address: %d.%d.%d.%d\n",
               arp_packet->arp_spa[0],
               arp_packet->arp_spa[1],
               arp_packet->arp_spa[2],
               arp_packet->arp_spa[3],
               arp_packet->arp_tpa[0],
               arp_packet->arp_tpa[1],
               arp_packet->arp_tpa[2],
               arp_packet->arp_tpa[3]);
        ////Data Collection for logging
        packetData.setSrcIp(castTo32bit(arp_packet->arp_spa));
        packetData.setDstIp(castTo32bit(arp_packet->arp_tpa));
        packetData.setAProtocol(0.1);
        ////Data Collection for logging


    } else {
        std::cout << "\t PACKET TYPE : "<<ntohs(ethernet->ether_type);
        ip = (struct ip_hdr *) (packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip >= 20) {
            std::cout << "\t Source IP Address : " << inet_ntoa(ip->ip_src) << "\t"
                      << "Destination IP Address : " << inet_ntoa(ip->ip_dst);
            ////Data Collection for logging
            packetData.setSrcIp(ip->ip_src.s_addr);
            packetData.setDstIp(ip->ip_dst.s_addr);
            ////Data Collection for logging
        }
        tcp = (struct tcp_hdr *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp >= 20) {
            std::cout << "\t Protocol : TCP " << " Source Port : " << tcp->th_sport << "\t"
                      << " Destination Port : " << tcp->th_dport << "\t Sequence : " << tcp->th_seq;
            ////Data Collection for logging
            packetData.setAProtocol(0.2);
        } else {
            udp = (struct udp_hdr *) (packet + SIZE_ETHERNET + size_ip);
            std::cout << "\t Protocol : UDP " << " Source Port : " << udp->sport << "\t"
                      << " Destination Port : " << udp->dport;
            ////Data Collection for logging
            packetData.setAProtocol(0.3);
        }

    }
    std::cout << std::endl;
    logToFile(packetData);

}