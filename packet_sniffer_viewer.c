#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
typedef unsigned char u_char;
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>


int get_inet(char *device_name,char *error)
{
    pcap_t *pack_desc;
    const u_char *packet;
    struct pcap_pkthdr headr;
    u_char *hard_ptr;
    struct ether_header *eptr;
    int i;

    pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    if (pack_desc == NULL)
    {
        fprintf(stderr, "Error opening device %s: %s\n", device_name, error);
        return -1;
    }

    packet = pcap_next(pack_desc, &headr);
    if (packet == NULL)
    {
        fprintf(stderr, "Error: cannot capture packet\n");
        return -1;
    }
    else
    {
        printf("Received a packet with length %d\n", headr.len);
        printf("Received at %s", ctime((const time_t *)&headr.ts.tv_sec));
        printf("Ethernet header length: %d\n", ETHER_HDR_LEN);

        eptr = (struct ether_header *)packet;
        printf("Ethernet type: 0x%x\n", ntohs(eptr->ether_type));

        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        {
            printf("Ethernet type hex: 0x%x; dec: %d is an IP Packet\n", ETHERTYPE_IP, ETHERTYPE_IP);
        }
        else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
        {
            printf("Ethernet type hex: 0x%x; dec: %d is an ARP Packet\n", ETHERTYPE_ARP, ETHERTYPE_ARP);
        }
        else
        {
            printf("Ethernet type hex: 0x%x; dec: %d is not an IP or ARP packet, skipping...\n", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
        }

        hard_ptr = eptr->ether_dhost;
        printf("Destination address: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            printf("%s%x", (i == 0) ? "" : ":", *hard_ptr++);
        }
        printf("\n");

        hard_ptr = eptr->ether_shost;
        printf("Source address: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
            printf("%s%x", (i == 0) ? "" : ":", *hard_ptr++);
        }
        printf("\n");

        printf("------------------------------------------------------------\n");
        pcap_close(pack_desc);
    }
}

int get_packet(char *device_name,char *error)
{
    int rcode;
    char *net_addr , *net_mask;
    bpf_u_int32 net_addr_int, net_mask_int;
    struct in_addr addr;

    rcode = pcap_lookupnet(device_name,&net_addr_int,&net_mask_int,error);
    if (rcode==-1)
    {
        printf("%s\n",error);
        return -1;
    }

    addr.s_addr = net_addr_int;
    net_addr = inet_ntoa(addr);
    if (net_addr == NULL)
    {
        printf("inet_ntoa : Error converting IP");
        return -1;
    }
    else
    {
        printf("NET : %s\n",net_addr);
    }
    addr.s_addr = net_mask_int;
    net_mask = inet_ntoa(addr);
    if (net_mask == NULL)
    {
        printf("inet_ntoa : Error converting MASK");
        return -1;
    }
    else
    {
        printf("MASK : %s\n",net_mask);
    }
    printf("------------------------------------------------------------\n");
}

int main(int argc, char const *argv[])
{
    char *device_name;
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0, ch;

    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Cannot acquire the device\n");
        return -1;
    }
    printf("The available devices are: \n");
    for (temp = interfaces; temp; temp = temp->next)
    {
        printf("#%d : %s\n", ++i, temp->name);
    }
    printf("Select the interfaces to Return the Repective packet descriptor : \n");
    scanf("%d", &ch);
    i = 1;
    device_name = NULL;
    for (temp = interfaces; temp; temp = temp->next)
	{
    	    if (i == ch)
    		{
        	    device_name = temp->name;
        	    break;
    		}
   	    i++;
	}

    if (device_name == NULL)
	{
    	    fprintf(stderr, "Invalid interface selection.\n");
    	    pcap_freealldevs(interfaces);
    	    return -1;
	}

    pcap_freealldevs(interfaces);
    get_packet(device_name,error);
    get_inet(device_name,error);
    return 0;
}
