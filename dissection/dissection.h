//
// Created by shubhangamg on 4/3/24.
//

#ifndef IDS_DISSECTION_H
#define IDS_DISSECTION_H
/**
 * Standard ports for application protocols
 */
#define PORT_FTP_DATA 20
#define PORT_FTP_CONTROL 21
#define PORT_SMTP 25
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_DNS 53
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_IMAP_UNENCRYPTED 143
#define PORT_IMAP_ENCRYPTED 993
#define PORT_POP3_UNENCRYPTED 110
#define PORT_POP3_ENCRYPTED 995
#define PORT_SIP 5060
#define PORT_XMPP 5222
#define PORT_NFS 2049
#define PORT_SMB 139
#define PORT_CIFS 445
#define PORT_RDP 3389
#define PORT_VNC 5900
#define PORT_RTMP 1935
#define PORT_RTP 16384
#define PORT_RTSP 554
#define PORT_SNMP 161
/**
 * End of Standard ports for application protocols
 */
/**
* Values of 'ethertype' in Ethernet II frame
*/
#define ETHER_LENGTH 0x05DC
#define ETHER_IPV4 0x0800
#define ETHER_ARP 0x0806
#define ETHER_RARP 0x0835
#define ETHER_VLAN 0x8100
#define ETHER_SNMP 0x814C
#define ETHER_STP 0x8181
#define ETHER_IPV6 0x86DD
#define ETHER_SECURE 0x876D
#define ETHER_PON 0x8808
#define ETHER_PPP 0x880B
#define ETHER_MPLS 0x8847
#define ETHER_PPPoE_DISCOVER 0x8863
#define ETHER_PPPoE_SESSION 0x8864
#define ETHER_LLDP 0x88CC
#define ETHER_LOOPBACK 0x9000
/**
* End of Values of 'ethertype' in Ethernet II frame
*/
#endif //IDS_DISSECTION_H
