#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ipheader {
	unsigned char      iph_ihl:5, iph_ver:4;
 	unsigned char      iph_tos;
 	unsigned short int iph_len;
 	unsigned short int iph_ident;
 	unsigned char      iph_flag;
 	unsigned short int iph_offset;
 	unsigned char      iph_ttl;
 	unsigned char      iph_protocol;
 	unsigned short int iph_chksum;
 	unsigned int       iph_sourceip;
 	unsigned int       iph_destip;
};

struct udpheader {
	unsigned short int udph_srcport;
 	unsigned short int udph_destport;
 	unsigned short int udph_len;
 	unsigned short int udph_chksum;
};

struct icmpheader {
 unsigned char      icmph_type;
 unsigned char      icmph_code;
 unsigned short int icmph_chksum;
 /* The following data structures are ICMP type specific */
 unsigned short int icmph_ident;
 unsigned short int icmph_seqnum;
};

struct tcpheader {
 unsigned short int   tcph_srcport;
 unsigned short int   tcph_destport;
 unsigned int     tcph_seqnum;
 unsigned int     tcph_acknum;
 unsigned char    tcph_reserved:4, tcph_offset:4;
 unsigned char    tcph_flags;
 unsigned short int   tcph_win;
 unsigned short int   tcph_chksum;
 unsigned short int   tcph_urgptr;
};

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;

    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);

}

int main(int argc, char *argv[])
{
	int sd;

	// This buffer will be used to construct raw packet.
	char buffer[1024];

	// Typecasting the buffer to the IP header structure
	struct ipheader *ip = (struct ipheader *) buffer;
	
	// Typecasting the buffer to the UDP header structure
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

	//Source and destination addresses: IP and port
	struct sockaddr_in sin, din;	

	//Clear buffer
	memset(buffer,0,1024);

	if(argc != 5)
	{
		printf("Please use 4 parameters: <<source hostname/IP> <source port> <target hostname/IP> <target port>");
		exit(-1);
	}
	else
	{
		// Assign value to the IP and UDP header fields.
		ip->field = ...;
		udp->field = ...;

		/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
		* tells the sytem that the IP header is already included;
		* this prevents the OS from adding another IP header. */
		
		sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(sd < 0) {
			perror("socket() error"); exit(-1);
		}
		printf("socket() OK. \n");
		/* This data structure is needed when sending the packets
		* using sockets. Normally, we need to fill out several
		* fields, but for raw sockets, we only need to fill out
		* this one field */

		sin.sin_family = AF_INET;

		/* Send out the IP packet.
		* ip_len is the actual size of the packet. */
		if(sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
			perror("sendto() error"); exit(-1);
		}
		
		return 0;
	}
}
