#ifndef __FT_PACKET_H
#define __FT_PACKET_H

#include<linux/if_ether.h>

//icmp types
#define ICMP_ECHOREP    0
#define ICMP_ECHO       8
#define ICMP_DSTUNRCH   3
#define ICMP_REDIRECT   5
#define ICMP_RTRADV     9
#define ICMP_RTRSOLCT   10
#define ICMP_TMEXC      11
#define ICMP_PRMPRB     12

//icmp destination unreachable codes
#define NET_UNREACH	0
#define HOST_UNREACH	1
#define PROTO_UNREACH	2
#define PORT_UNREACH	3
#define FRAG_NEEDED	4
#define SRCRT_FAILED	5

//return codes		
#define SUCCESS		0
#define MALFORMED	1
#define INSUFF_DATA	2
#define WRONG_PROTO	3
#define WRONG_HOST	4
#define WRONG_ID	5
#define LOW_TTL		6

/*
struct arp_hdr{
	unsigned short	arp_hrd;
	unsigned short	arp_pro;
	unsigned char 	arp_hlen;
	unsigned char	arp_plen;
	unsigned short	arp_op;
	unsigned char	arp_sha[ETH_ALEN];
	unsigned int	arp_spa;
	unsigned char	arp_tha[ETH_ALEN];
	unsigned int	arp_tpa;
};
*/

//NOTE: on little endian systems, bitwise members of structures
//that are defined first are less significant than what comes after
//so we must reverse the order of their definition for network header structures,

//I assume that means most significant bits are queued first on the wire by the driver

//however on both little and big endian systems, byte based variables that
//are defined first are assigned lower memory than those that are defined
//after them, so the order is aligned with network byte order
typedef struct{
#if __BYTE_ORDER_ == __LITTLE_ENDIAN_
	unsigned char hl:4,
			v:4;
#else 
	unsigned char v:4,
			hl:4;
#endif
	unsigned char tos;
	unsigned short tlen;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char proto;
	unsigned short chksum;
	unsigned int saddr;
	unsigned int daddr;
}iphdr;

#define IPADDR_LEN	4

typedef struct{
	unsigned int flow;
	unsigned short plen;
	unsigned char nxthdr;
	unsigned char hoplmt;
	unsigned char saddr[16];
	unsigned char daddr[16];
	
}ip6hdr;

#define IP6ADDR_LEN	16


typedef struct{
	unsigned char type;
	unsigned char code;
	unsigned short chksum;
	unsigned short id;
	unsigned short seq;
	char data[1];
}icmphdr;
#define ICMP_HLEN 8

typedef struct{
	unsigned short sport;
	unsigned short dport;
	unsigned short len;
	unsigned short chksum;
}udphdr;

typedef struct{
	unsigned short sport;
	unsigned short dport;
	unsigned int seq;
	unsigned int ack;
# if __BYTE_ORDER_ == __LITTLE_ENDIAN_
	unsigned char res:4,
			off:4;
# else /*BIG ENDIAN*/
	unsigned char off:4,
			res:4;
# endif
	unsigned char flags;
# define FIN 0x1
# define SYN 0x2
# define RST 0x4
# define PSH 0x8
# define ACK 0x10
# define URG 0x20
	unsigned short win;
	unsigned short chksum;
	unsigned short urgent;
}tcphdr;

//CHECK: should support ipv6 as well
struct pseudo_hdr {
	unsigned int saddr;
	unsigned int daddr;
	unsigned char zero;
	unsigned char proto;
	unsigned short len;//ip data_len
};

struct l3_hdr{
 union{
//      arphdr  arp;//may omit this
        iphdr   ip;
        ip6hdr  ip6;
 }l3u;
};

struct l4_hdr{
 union{
        icmphdr icmp;
        udphdr  udp;
        tcphdr  tcp;
 }l4u;
};

/*Macros for easier access*/
#define p_arp   l3u.arp
#define p_ip    l3u.ip
#define p_ip6   l3u.ip6
#define _icmp  l4u.icmp
#define _udp   l4u.udp
#define _tcp   l4u.tcp

typedef struct{
	unsigned short id;
	unsigned short flags;
	unsigned short num_quest;
	unsigned short num_rr;
	unsigned short num_auth_rr;
	unsigned short num_add_rr;
	unsigned char data[1];
}dns_hdr;
#define DNS_HLEN	12


typedef struct {
	char *qname;
	unsigned char qlen;
	unsigned short qtype;
	unsigned short qclass;
	struct dns_quest *next_query_ptr;
}dns_quest;
#define MAX_DNS_QUERY	128

typedef struct dns_rr{
	//domain_name_prt;
	//type;
	//class;
	//ttl;
	//rdata_len;
	//rdata_ptr;
	//next_rr_ptr;
}dns_rr;

struct bgp{
};


#endif //__FT_PACKET_H
