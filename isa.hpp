
#ifndef __ISA_HPP__
#define __ISA_HPP__

#include <pcap.h>
#include <netdb.h>
#include <unistd.h>
#include <utility>
#include <string>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>

typedef in_addr pcap_ip;
typedef char* string_ip;
typedef u_short pcap_port;
typedef uint8_t protocol;
typedef uint8_t tos;
typedef struct timeval timeval_s;

#define __FAVOR_BSD     // so this works on merlin.fit.vutbr.cz
#define newString(string_ip) new char
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6
#define UDP_BUFF_SIZE 1024
#define NETFLOW_V5_DATASIZE 576         // header 24*8, record 48*8

#define ISA_VERBOSE_PRINT false    // talk more in cmd-line

#define ISA_RETURN_OK 0
#define ISA_RETURN_ARGERR 1
#define ISA_RETURN_NOPCAP 2
#define ISA_RETURN_FILTERPARSE 30
#define ISA_RETURN_FILTERINSTALL 31
#define ISA_RETURN_UDP_HOSTNAME 40
#define ISA_RETURN_UDP_SOCKET 41
#define ISA_RETURN_UDP_CONNECT 42
#define ISA_RETURN_UDP_SEND 43
#define ISA_RETURN_UDP_PARTIALSEND 44
#define ISA_RETURN_UDP_ANY 45
#define ISA_RETURN_PCAPPROTOCOL 50
#define ISA_RETURN_PCAPHEADER 51

/** ICMP **/
/*
struct sniff_icmp {
    u_char type;
    u_char code;
    u_short checksum;
    u_int rest_of_header;
};*/


/** UDP **/
struct sniff_udp {
    u_short src_port;
    u_short dst_port;
    u_short length;
    u_short checksum;
};

// Ethernet header - code is from: https://www.tcpdump.org/pcap.html
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

// IP header - code is from: https://www.tcpdump.org/pcap.html 
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

// TCP header - code is from: https://www.tcpdump.org/pcap.html
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */

    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/** Supported protocol numbers **/
enum protocolNumber {
    ICMP = 1,
    TCP = 6,
    UDP = 17
};

#endif