#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define PACKET_LEN 512

int main()
{
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create a raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Turn on promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
               sizeof(mr));


    int count;
    char buffer[IP_MAXPACKET];
    int data_size;
    count = 0;

    printf("------ Sniffing ICMP Packets... ------\n--------------------------------------\n");
    // Getting captured packets
    while (1)
    {       
        
        data_size = recvfrom(sock, buffer, PACKET_LEN, 0,
                                 &saddr, (socklen_t *)sizeof(saddr));
        struct iphdr *ip_hdr = (struct iphdr *)(buffer + ETH_HLEN);

        // Print all ICMP packets by filtering IP Header of kind ICMP.
        if (ip_hdr->protocol == IPPROTO_ICMP)
        {
            // struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ETH_HLEN + (ip_hdr->ihl * 4));
            struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));

            int t = (unsigned int)(icmp_hdr->type);
            int c = (unsigned int)(icmp_hdr->code);

            // ICMP header of type 0 is Echo (Reply), and type 8 is Echo.
            // We capture our sent ping to 8.8.8.8(Echo),
            // or Echo replies from outside.
            if (t == 0 || t == 8)
            {
                count++;
                // Get source IP Address:
                struct sockaddr_in source, dest;
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip_hdr->saddr;

                // Get destination IP Address:
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = ip_hdr->daddr;


                printf("ICMP Packet Found: (%d)\n", count);
                printf("IP Addresses:\n");
                printf("Source: %s\n", inet_ntoa(source.sin_addr));
                printf("Destination: %s\n", inet_ntoa(dest.sin_addr));
                printf("ICMP Details:\n");
                printf("type: %d\n", t);
                printf("code: %d\n", c);
                printf("--------------------\n");
            }
        }
    }
    close(sock);
    return 0;
}