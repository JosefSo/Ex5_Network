#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char*argv[]) 
{

    int PACKET_LENGTH = 512;
    char buff[IP_MAXPACKET];
    int packet_num = 1;
    
    struct packet_mreq mr;
    struct sockaddr saddr;
    

    // Creates RAW socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock==-1){
    perror("error socket");
    return -1;
    }

    // Turning on the promiscuous mode. 
    mr.mr_type = PACKET_MR_PROMISC;                           
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,  sizeof(mr));

    // Gets captured packets
    while (1) 
    {
    	  bzero(buff,IP_MAXPACKET);
        int data_size=recvfrom(sock, buff, ETH_FRAME_LEN, 0,  NULL, NULL);
        if(data_size>0) {
            
            
            // get packet itself:
            char *all_types[] = {
                "Type 0 — Echo Reply",
                "Type 1 — Unassigned",
                "Type 2 — Unassigned",
                "Type 3 — Destination Unreachable",
                "Type 4 — Source Quench (Deprecated)",
                "Type 5 — Redirect",
                "Type 6 — Alternate Host Address (Deprecated)",
                "Type 7 — Unassigned",
                "Type 8 — Echo",
                "Type 9 — Router Advertisement",
                "Type 10 — Router Selection",
                "Type 11 — Time Exceeded",
                "Type 12 — Parameter Problem",
                "Type 13 — Timestamp",
                "Type 14 — Timestamp Reply",
                "Type 15 — Information Request (Deprecated)",
                "Type 16 — Information Reply (Deprecated)",
                "Type 17 — Address Mask Request (Deprecated)",
                "Type 18 — Address Mask Reply (Deprecated)",
                "Type 19 — Reserved (for Security)",
                "Types 20-29 — Reserved (for Robustness Experiment)",
                "Type 30 — Traceroute (Deprecated)",
                "Type 31 — Datagram Conversion Error (Deprecated)",
                "Type 32 — Mobile Host Redirect (Deprecated)",
                "Type 33 — IPv6 Where-Are-You (Deprecated)",
                "Type 34 — IPv6 I-Am-Here (Deprecated)",
                "Type 35 — Mobile Registration Request (Deprecated)",};


            short ipHeaderLen;
            struct iphdr *iph = (struct iphdr *)(buff+ETH_HLEN);
            

            if (iph->protocol== IPPROTO_ICMP) {
                ipHeaderLen = iph->ihl * 4;
                struct icmphdr *icmph = (struct icmphdr *) (buff + ipHeaderLen +ETH_HLEN);
                
                if ((unsigned int) (icmph->type) <= 10) {

                    //Source:
                    struct sockaddr_in src;
                    memset(&src, 0, sizeof(src));
                    src.sin_addr.s_addr = iph->saddr;

                    //Destination:
                    struct sockaddr_in dest;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = iph->daddr;
                    
                    //Prints:
                    printf("\n");
                    printf("ICMP Packet number %d:\n", packet_num);
                    printf("Source IP is: %s\n", inet_ntoa(src.sin_addr));
                    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
                    printf("ICMP Echo type is: %s\n", all_types[icmph->type]);
                    printf("ICMP Echo code is: %d\n", icmph->code);
                    
                    packet_num++;

                }
            }
        }
    }

    close(sock);
    return 0;
}