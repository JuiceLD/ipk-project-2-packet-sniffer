/**
 *  @file 		packet_sniffer.c
 *  @author		Adam Bazel
 *  @date		24. 04. 2021
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <pcap.h>		// The backbone library of this program
#include <time.h>		// Used for printing time in certain format

#include <netinet/ip_icmp.h>	// Provides declarations for icmp header
#include <netinet/udp.h>	// Structure I picked for getting ip addresses and ports
#include <netinet/ip6.h>	// Provides declarations for ip6 header

#include <arpa/inet.h> 		// For inet_ntoa() and inet_ntop()

#include <net/ethernet.h>	// Provides the size of ether header and ether addresses

#define MAXBYTES2CAPTURE 2048	// The maximum length able to be set on the handle


/**
 * 	@brief Variables for flags from getopt()
 */
bool arp_flag;
bool icmp_flag;
bool tcp_flag;
bool udp_flag;
bool inter_flag;
bool port_flag;
bool number_flag;

/**
 *  @brief Prints out the payload and its description in specific manner.
 *  @param data Payload data (const u_char*)
 *  @param size Payload size (int)
 *  @note Modified from: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void print_data(const u_char* data, int size)
{
	int i , j;
	for (i = 0; i < size; i++)
	{
		// Padding
		if (i != 0 && i % 16 == 0)
		{
			printf("  ");
			// Print out the payload by 16 elements
			for (j = i - 16; j < i; j++)
			{
				if(data[j] >= 32 && data[j] <= 128)
        			{
					printf("%c",(unsigned char)data[j]);
           			}
				else
                		{
                			printf(".");
                		}

			}
			printf("\n");
		}

		// Hex number
		if (i % 16 == 0)
        	{
            		if (i == 0)
            		{
            	   		printf("0x0000 ");
            		}
            		else
            		{
               	    		printf("%#06x ", i);
            		}
        	}

		// Print payload in hexadecimal number
		printf(" %02x",(unsigned int)data[i]);

		// Print last row (almost the same)
		if (i == size - 1)
		{
			// Padding so it keeps the format shape
			for (j = 0; j < 15 - i % 16; j++)
			{
			    printf("   ");
			}
			printf("  ");

			for ( j = i - i % 16; j <= i; j++)
			{
				if ( data[j] >= 32 && data[j] <= 128)
				{
				    printf("%c",(unsigned char)data[j]);
				}
				else
				{
				    printf(".");
				}
			}
			printf("\n");
		}
	}
	printf("\n");
}

/**
 *  @brief Funtion that prints out time in RFC3339 format.
 *  @note Modified from: https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc
 */
void print_time()
{
    time_t now = time(NULL);
    struct tm *tm;
    int off_sign;
    int off;

    struct timeval time;
    gettimeofday(&time, NULL);

    tm = localtime(&now);
    off_sign = '+';
    off = (int) tm->tm_gmtoff;
    if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }

    printf("%d-%02d-%dT%02d:%02d:%02d.%03d%c%02d:%02d ",
          tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec, (int) time.tv_usec / 1000,
          off_sign, off / 3600, off % 3600);

    return;
}

/**
 *  @brief Funtion that prints out ethernet source and destination address.
 */
void print_ethernet_adress(const u_char *packet)
{
	struct ethhdr *eth = (struct ethhdr *)packet;

	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x > ", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x,  ", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
}

/**
 *  @brief Funtion that prints out source and destination ipv4 address with ports.
 */
void print_address(struct iphdr *iph, const u_char* packet)
{
	unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ethhdr));

	char source4[INET_ADDRSTRLEN];
	char destin4[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(iph->saddr), source4, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iph->daddr), destin4, INET_ADDRSTRLEN);

	printf("%s : %d > " , source4, ntohs(udph->source));
	printf("%s : %d, ", destin4, ntohs(udph->dest));

	return;
}

/**
 *  @brief Funtion that prints out source and destination ipv6 address with ports.
 */
void print_6address(const u_char* packet)
{
	const struct ip6_hdr *ipv6_header;
	ipv6_header = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
	struct udphdr *udph6 = (struct udphdr*)(packet + sizeof(struct ip6_hdr) + sizeof(struct ethhdr));

	char source6[INET_ADDRSTRLEN];
	char destin6[INET_ADDRSTRLEN];

	inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source6, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destin6, INET6_ADDRSTRLEN);

	printf("%s : %d > ", source6, ntohs(udph6->source));
	printf("%s : %d, ", destin6, ntohs(udph6->dest));

	return;
}

/**
 *  @brief Funtion that determines type of protocol and prints out neccesary info about packet.
 *  @param arg Arguments (not used) (u_char *)
 *  @param pkthdr Packet header (const struct pcap_pkthdr*)
 *  @param packet Packet data (const u_char *)
 */
void process_packet(u_char * arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    int size = pkthdr->len;

    print_time();

    // Check the Protocol
    switch (iph->protocol)
    {
	case 1:  // ICMP Protocol
	case 6:  // TCP Protocol
	case 17: // UDP Protocol
	switch (iph->version)
	{
		case 4:
			print_address(iph, packet);
			break;
		case 6:
			print_6address(packet);
			break;
		default:
			fprintf(stderr, "Error: Wrong packet address type!\n");
		 	exit(1);
	}
	break;

	default: // ARP Protocol
		print_ethernet_adress(packet);
		break;
     }

     printf("length %d bytes\n", pkthdr->len);
     print_data(packet, size);

     return;
}

/**
 *  @brief Funtion creates and puts together filter expression for pcap filter function based on program arguments.
 *  @param filter_flags Amount of flags raised by user arguments that impact the filter (int)
 *  @param port_value Port number(unsigned int)
 *  @param filter_string String array where the filter expression is saved (char * )
 *  @return String array with the filter expression in correct format
 */
char* process_filter(int filter_flags, unsigned int port_value, char * filter_string)
{
    char buffer[20];

    // Incorrect device
    if (inter_flag == false)
    {
        fprintf(stderr, "Error: No device entered!\n");
        exit(1);
    }

    // No arguments except with correct device
    if (filter_flags == 0 && port_flag == false)
    {
        strcat(filter_string ,"tcp or udp or icmp or icmp6 or arp");
    }

    // Port and interface was in the arguments but no others were filled
    if (filter_flags == 0 && port_flag == true)
    {
        strcat(filter_string ,"tcp port ");
        sprintf(buffer, "%d ", port_value);
        strcat(filter_string, buffer);
        strcat(filter_string ,"or udp port ");
        sprintf(buffer, "%d or ", port_value);
        strcat(filter_string, buffer);
        strcat(filter_string ,"icmp or icmp6 or arp");
    }

    // Interface was filled but no port, now search which
    // flags were raised and print expressions accordingly
    while (filter_flags != 0)
    {
        if (tcp_flag)
        {
            strcat(filter_string, "tcp");
            if (port_flag)
            {
                strcat(filter_string, " port ");
                sprintf(buffer, "%d", port_value);
                strcat(filter_string, buffer);
            }
            tcp_flag = false;
            filter_flags--;
            if (filter_flags != 0)
            {
                strcat(filter_string, " or ");
            }
        }

        if (udp_flag)
        {
            strcat(filter_string, "udp");
            if (port_flag)
            {
                strcat(filter_string, " port ");
                sprintf(buffer, "%d", port_value);
                strcat(filter_string, buffer);
            }
            udp_flag = false;
            filter_flags--;
            if (filter_flags != 0)
            {
                strcat(filter_string, " or ");
            }
        }

        if (icmp_flag)
        {
            strcat(filter_string, "icmp or icmp6");
            icmp_flag = false;
            filter_flags--;
            if (filter_flags != 0)
            {
                strcat(filter_string, " or ");
            }
        }

        if (arp_flag)
        {
            strcat(filter_string, "arp");
            icmp_flag = false;
            filter_flags--;
            if (filter_flags != 0)
            {
                strcat(filter_string, " or ");
            }
        }
    }

    return filter_string;
}

int main (int argc, char **argv)
{
    char inter_value[128];
    unsigned int packet_count = 1;
    unsigned int port_value;

    int filter_flags = 0;
    int opt = 0;
    char *ptr;

    // Modified getopt() that parses arguments from:
    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    static struct option long_options[] =
    {
        {"interface", optional_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 3},
        {"icmp", no_argument, 0, 4},
        {0, 0, 0, 0}
    };

    int counter = 1;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "tup:n:i::", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 1:
                break;

            case 't':
                tcp_flag = true;
                filter_flags++;
                counter++;
                break;

            case 'u':
                udp_flag = true;
                filter_flags++;
                counter++;
                break;

            case 'i':
                inter_flag = true;

                while (argv[counter] != NULL && argv[counter][0] == '-')
		{
		    counter++;
		}
                if (argv[counter] != NULL && isalpha(argv[counter][0]))
                {
                	  strcpy(inter_value, argv[counter]);
                }
                else
                {
                  	// Print out all devs example from:
                  	// http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
        	    	char error[PCAP_ERRBUF_SIZE];
  			pcap_if_t *interfaces,*temp;

			if (pcap_findalldevs(&interfaces, error) == -1)
			{
			        printf("\nError: in pcap findall devs!");
			        return 1;
  			}

			for (temp = interfaces; temp; temp = temp->next)
			{
			        printf("%s\n", temp->name);
      		    	}
			exit(0);
                }

                counter++;
                break;

            case 'n':
                number_flag = true;
       		while (argv[counter] != NULL && argv[counter][0] == '-')
      		{
        	    counter++;
        	}
                if (argv[counter] == NULL)
                {
                	fprintf(stderr, "Error: Something went wring during parsing arguments!\n");
                    return 1;
                }
                packet_count = strtoul(argv[counter], &ptr, 10);

                counter++;
                break;

            case 'p':
                port_flag = true;

                while (argv[counter] != NULL && argv[counter][0] == '-')
       		{
        	    counter++;
        	}

                if (argv[counter] == NULL)
                {
		    fprintf(stderr, "Error: Something went wring during parsing arguments\n");
                    return 1;
                }

                port_value = strtoul(argv[counter], &ptr, 10);

                counter++;
                break;

            case 3:
                arp_flag = true;
                filter_flags++;
                counter++;
                break;

            case 4:
                icmp_flag = true;
                filter_flags++;
                counter++;
                break;

            case ':':
                fprintf(stderr, "%s: option '-%c' requires an argument\n", argv[0], optopt);

            case '?':
                return 1;

            default:
                return 1;
        }
    }

    char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces,*temp;

    // Incorrect device
    if (inter_flag == false)
    {
		if (pcap_findalldevs(&interfaces, error) == -1)
		{
				printf("\nError: in pcap findall devs!");
				return 1;
		}

		for (temp = interfaces; temp; temp = temp->next)
		{
			printf("%s\n", temp->name);
		}
		exit(0);
    }

   /** Packet Sniffer Functions
     * Sources:
     * Example: https://www.tcpdump.org/pcap.html
     * Example: https://github.com/lsanotes/libpcap-tutorial/blob/master/simplesniffer.c
     */
    char filter_commands[256] = "";
    strcpy(filter_commands, process_filter(filter_flags, port_value, filter_commands));

    int count=0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;

    device = inter_value;

    // Open the network device for packet capture
    if ((descr = pcap_open_live(device, MAXBYTES2CAPTURE, 0,  512, errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        return 1;
    }

    unsigned int source, mask;
    struct bpf_program filter;

    // Look up the network address and subnet mask for the network device. Only mask will be used
    if (pcap_lookupnet(device, &source, &mask, errbuf) < 0)
    {
        printf("Error: In function pcap_lookupnet: %s\n", errbuf);
        return 1;
    }

    // The filter will be converted from a text string to a bpf program
    if (pcap_compile(descr, &filter, filter_commands, 1, mask))
    {
        printf("Error: In function pcap_compile(): %s\n", pcap_geterr(descr));
        printf("%s\n", filter_commands);
        return 1;
    }

    // Load the compiled filter program into the packet capture device
    if (pcap_setfilter(descr, &filter) < 0)
    {
        printf("Error: In function pcap_setfilter(): %s\n", pcap_geterr(descr));
        return 1;
    }

    // Read and process certain amount of packets that will match the filter
    if (pcap_loop(descr, packet_count, process_packet, (u_char *)&count) == -1)
    {
        fprintf(stderr, "Error: %s\n", pcap_geterr(descr) );
        return 1;
    }

    // Close the network
    pcap_close(descr);

    return 0;
}