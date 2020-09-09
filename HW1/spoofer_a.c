#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

struct ipheader {
	 unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
	 unsigned char ip_tos;
	 unsigned short int ip_len;
	 unsigned short int ip_id;
	 unsigned short int ip_off;
	 unsigned char ip_ttl;
	 unsigned char ip_p;
	 unsigned short int ip_sum;
	 unsigned int ip_src;
	 unsigned int ip_dst;
}; /* total ip header length: 20 bytes (=160 bits) */

struct udpheader {
	 unsigned short int uh_sport;
	 unsigned short int uh_dport;
	 unsigned short int uh_len;
	 unsigned short int uh_check;
}; /* total udp header length: 8 bytes (=64 bits) */

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;

    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);

}

int main(int argc, char* argv[])
{
	char ip1[100];
	char ip2[100];
	char port1[10];
	char port2[10];
	printf("Welcome to Spoofer.\n");
	printf("Please enter Source IP:\n");
	scanf("%s",ip1);
	printf("Please enter source port number:\n");
	scanf("%s",port1);
	printf("Please enter Destination IP:\n");
	scanf("%s",ip2);
	printf("Please enter Destination port number:\n");
	scanf("%s",port2);

	int sd;
	struct sockaddr_in sin;
	char buffer[4096];
	struct ipheader *ip = (struct ipheader *) buffer;
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
	sd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	if(sd < 0){
		perror("socket() error");
		return -1;
	}
	printf("socket() - Using Raw socket and UDP protocol");
	sin.sin_family = AF_INET;

	memset (buffer, 0, 4096);	/* zero out the buffer */
	/* we'll now fill in the ip/tcp header values, see above for explanations */
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_tos = 0;
	ip->ip_len = sizeof (struct ipheader) + sizeof (struct udpheader);	/* no payload */
	ip->ip_id = htons (54321);	/* the value doesn't matter here */
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = 17; //udp protocol
	ip->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
	ip->ip_src = inet_addr("10.0.2.4");
	ip->ip_dst = inet_addr("10.0.2.15");
	udp->uh_sport = htons(8080);
	udp->uh_dport = htons(21);
	udp->uh_len = htons(sizeof(struct udpheader));
	udp->uh_check = 0;

	ip->ip_sum = csum ((unsigned short *) buffer, ip->ip_len >> 1);

	//make sure the kernel knows the header is included 
	int one = 1;
    const int *val = &one;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
      	printf ("Warning: Cannot set HDRINCL!\n");
    }
    printf("Sending Spoof packet using UDP....\n");

    int count;
    for(count=1; count <=20; count++);
    {
    	printf("hello");
    	if(sendto(sd, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			perror("sendto() error"); 
			return -1;
		}
		printf("Succes spoofing.\n");
    }
	return 0;
}