#include"ft_net.h"

/*convert a numerical prefix to equivalent subnet mask*/
//returns mask in network byte-order
prfx_to_msk(int prefix, char ip_v, int *result) {

        register int mask = 0;

        int bit;

        for(bit = 31; bit > (31 - prefix); bit--) {
                mask |= (1 << bit);
        }

//printf("mask is: ");
//fprint_addr(stdout,mask);

        *result = htonl(mask);//must be stored in "struct subnet" in network byte-order

//CHECK IPv6

}


/*ip_addr is in host byte-order*/
int
fprint_addr(FILE *file,unsigned int ip_addr) {

        fprintf(file,"%d.%d.%d.%d\n",
                ip_addr>>24,
                (ip_addr>>16) & 0xff,
                (ip_addr>>8) & 0xff,
                ip_addr & 0xff);

}


/*ip_addr is in host byte-order*/
int
sprint_addr(char *buf, unsigned int ip_addr) {

	return sprintf(buf,"%d.%d.%d.%d\n",
			ip_addr>>24,
			(ip_addr>>16) & 0xff,
			(ip_addr>>8) & 0xff,
			ip_addr & 0xff);

}

int
fprint_mac(FILE *file,struct ethhdr *ethp) {

        int i;
        fprintf(file,"source MAC:\t");
        for(i = 0; i < 6; i++){
                i == 5 ? fprintf(file,"%02x",ethp->h_source[i])
                        : fprintf(file,"%02x:",ethp->h_source[i]);
        }fprintf(file,"\n");

        fprintf(file,"dest MAC:\t");
        for(i = 0; i < 6; i++){
                i == 5 ? fprintf(file,"%02x",ethp->h_dest[i])
                        : fprintf(file,"%02x:",ethp->h_dest[i]);
        }fprintf(file,"\n");
}

unsigned short
in_chksum(short *pkt,int len){
//printf("chksum ptr received %p\n",pkt);
        int left = len;
        unsigned int sum = 0;
        unsigned short *w = pkt;
        unsigned short answer = 0;


        while(left>1){
                sum += *w++;
                left-=2;
        }

        if(left == 1){
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum+=answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;

}


int
mac_cmp(char mac1[],char mac2[]) {//currently unused but might be needed when we VPN support

        return memcmp(mac1,mac2,6);
};





/*
int
is_egress(struct l3_hdr *l3, int ip_flg) {


        if(ip_flg == 0) { //ipv4
                unsigned int addr;
                
                addr = ntohl(l3->p_ip.ip_saddr);
                
        //if l3->p_ip.ip_saddr is in our network range
                if( (addr & (globlcf.cf_ipnet_msk)) == globlcf.cf_ipnet)
                        return 1;
                else
                        return 0;
        }else {//ipv6 CHECK
                //how to check if it's in range
                //same
        }
}
*/

