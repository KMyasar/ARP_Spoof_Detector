/**
 * @file arp_spoof_detect.c
 * @brief ARP Spoofing Detector
 * @version 0.1
 * @date 2025
 * @author Mohamed Yasar Arafath
 * 
 * @description
 * This program monitors network interfaces for ARP (Address Resolution Protocol) 
 * packets and detects potential ARP spoofing attacks based on packet frequency 
 * analysis. It uses the libpcap library for packet capture and provides 
 * real-time monitoring capabilities.
 * 
 * @warning
 * This tool requires root privileges to capture network packets and should 
 * only be used on networks you own or have explicit permission to monitor.
 * 
 * @dependencies
 * - libpcap-dev: Packet capture library
 * - libnotify-bin: Desktop notification system
 * 
 * @compilation
 * gcc -o arp_spoof_detect arp_spoof_detect.c -lpcap -Wall -Wextra -O2
 * 
 * @usage
 * sudo ./arp_detector -i <interface>
 */

/* Standard C Library Headers */
#include <stdio.h>              /* Standard I/O operations */
#include <string.h>             /* String manipulation functions */
#include <stdlib.h>             /* Standard library functions (malloc, exit, etc.) */
#include <errno.h>              /* Error number definitions */
#include <time.h>               /* Time functions for timestamp operations */
#include <unistd.h>             /* UNIX standard definitions (access, etc.) */

/* Network Programming Headers */
#include <sys/socket.h>         /* Socket programming definitions */
#include <netinet/in.h>         /* Internet address family structures */
#include <arpa/inet.h>          /* Internet operations (htons, etc.) */
#include <netinet/if_ether.h>   /* Ethernet protocol definitions */
#include <net/ethernet.h>       /* Ethernet header structures */

/* Packet Capture Library */
#include <pcap.h>               /* libpcap packet capture library */

/* ============================================================================
 * CONSTANTS AND MACROS
 * ============================================================================ */

/** @brief ARP Request operation code as defined in RFC 826 */
#define ARP_REQUEST 1

/** @brief ARP Response operation code as defined in RFC 826 */
#define ARP_RESPONSE 2

/** @brief Maximum time window for packet counting (seconds) */
#define DETECTION_WINDOW 20

/** @brief Threshold for suspicious packet count within time window */
#define PACKET_THRESHOLD 10

/** @brief Maximum length for formatted MAC address string */
#define MAC_ADDR_LEN 18

/** @brief Maximum length for formatted IP address string */
#define IP_ADDR_LEN 16

/** @brief Program version string */
#define VERSION "0.1"

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * @struct arp_header
 * @brief ARP packet header structure as defined in RFC 826
 * 
 * This structure represents the format of an ARP packet header.
 * All multi-byte fields are in network byte order and must be
 * converted using ntohs() for proper interpretation.
 */
typedef struct arp_header {
    uint16_t htype;             /**< Hardware type (1 = Ethernet) */
    uint16_t ptype;             /**< Protocol type (0x0800 = IPv4) */
    uint8_t  hlen;              /**< Hardware address length (6 for Ethernet) */
    uint8_t  plen;              /**< Protocol address length (4 for IPv4) */
    uint16_t opcode;            /**< Operation code (1=request, 2=reply) */
    uint8_t  sender_mac[6];     /**< Sender hardware address (MAC) */
    uint8_t  sender_ip[4];      /**< Sender protocol address (IP) */
    uint8_t  target_mac[6];     /**< Target hardware address (MAC) */
    uint8_t  target_ip[4];      /**< Target protocol address (IP) */
} arp_header_t;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */

/**
 * @brief Display alert when potential ARP spoofing is detected
 * @param ip String representation of attacker's IP address
 * @param mac String representation of attacker's MAC address
 */
void alert_spoof(const char *ip, const char *mac);

/**
 * @brief Print list of available network interfaces
 * @return 0 on success, -1 on error
 */
int print_available_interfaces(void);

/**
 * @brief Print program version and banner information
 */
void print_version(void);

/**
 * @brief Print program usage help information
 * @param program_name Name of the executable for usage examples
 */
void print_help(const char *program_name);

/**
 * @brief Convert binary MAC address to formatted string
 * @param mac 6-byte MAC address array
 * @return Dynamically allocated string in format "XX:XX:XX:XX:XX:XX"
 * @warning Caller must free returned memory
 */
char* format_mac_address(const uint8_t mac[6]);

/**
 * @brief Convert binary IP address to formatted string
 * @param ip 4-byte IP address array
 * @return Dynamically allocated string in dotted decimal format
 * @warning Caller must free returned memory
 */
char* format_ip_address(const uint8_t ip[4]);

/**
 * @brief Main packet capture and analysis function
 * @param device_name Name of network interface to monitor
 * @return 0 on normal termination, -1 on error
 */
int sniff_arp_packets(const char *device_name);

/**
 * @brief Check if required system dependencies are available
 * @return 0 if all dependencies present, -1 otherwise
 */
int check_dependencies(void);

/* ============================================================================
 * FUNCTION IMPLEMENTATIONS
 * ============================================================================ */

/**
 * @brief Display alert when potential ARP spoofing is detected
 * 
 * This function is called when the detection algorithm identifies
 * suspicious ARP traffic patterns that may indicate a spoofing attack.
 * 
 * @param ip String representation of suspected attacker's IP address
 * @param mac String representation of suspected attacker's MAC address
 */
void alert_spoof(const char *ip, const char *mac) {
    if (!ip || !mac) {
        fprintf(stderr, "Error: Invalid parameters passed to alert_spoof()\n");
        return;
    }
    
    /* Print alert to console with timestamp */
    time_t current_time = time(NULL);
    char *time_str = ctime(&current_time);
    
    /* Remove newline from time string */
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
    }
    
    printf("\n[%s] SECURITY ALERT: Potential ARP Spoofing Detected!\n", 
           time_str ? time_str : "Unknown time");
    printf("Suspected Attacker - IP: %s, MAC: %s\n", ip, mac);
    printf("Recommendation: Investigate network traffic immediately.\n\n");
    
    /* TODO: Add desktop notification using libnotify */
    /* TODO: Add logging to file */
    /* TODO: Add email notification capability */
}

/**
 * @brief Print list of available network interfaces
 * 
 * Uses libpcap to enumerate all network interfaces available
 * on the system for packet capture operations.
 * 
 * @return 0 on success, -1 on error
 */
int print_available_interfaces(void) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;
    pcap_if_t *current_interface = NULL;
    int interface_count = 0;
    
    /* Get list of all network interfaces */
    if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
        fprintf(stderr, "Error: Cannot enumerate network interfaces: %s\n", 
                error_buffer);
        return -1;
    }
    
    /* Check if any interfaces were found */
    if (!interfaces) {
        printf("No network interfaces found.\n");
        return 0;
    }
    
    printf("\nAvailable Network Interfaces:\n");
    printf("============================================\n");
    
    /* Iterate through interface list and display information */
    for (current_interface = interfaces; 
         current_interface != NULL; 
         current_interface = current_interface->next) {
        
        interface_count++;
        printf("#%d: %s", interface_count, current_interface->name);
        
        /* Display description if available */
        if (current_interface->description) {
            printf(" (%s)", current_interface->description);
        }
        
        printf("\n");
    }
    
    printf("============================================\n");
    printf("Total interfaces found: %d\n\n", interface_count);
    
    /* Free the interface list allocated by pcap_findalldevs */
    pcap_freealldevs(interfaces);
    
    return 0;
}

/**
 * @brief Print program version and banner information
 * 
 * Displays ASCII art banner along with version information
 * and brief program description.
 */
void print_version(void) {
    printf("\n");
    printf("   /   |  / __ \\/ __ \\                    \n");
    printf("  / /| | / /_/ / /_/ /                    \n");
    printf(" / ___ |/ _, _/ ____/                     \n");
    printf("/_/__|_/_/ |_/_/_________________________ \n");
    printf("  / ___// | / /  _/ ____/ ____/ ____/ __ \\ \n");
    printf("  \\__ \\/  |/ // // /_  / /_  / __/ / /_/ /\n");
    printf(" ___/ / /|  // // __/ / __/ / /___/ _, _/ \n");
    printf("/____/_/_|_/___/_/ __/_/   /_____/_/ |_|  \n");
    printf("\n");
    printf("LAHTP ARP Spoof Detector v%s\n", VERSION);
    printf("============================================\n");
    printf("Network Security Tool for ARP Spoofing Detection\n");
    printf("Monitors ARP packets and detects suspicious patterns\n");
    printf("\nStatus: Beta Version - Use with caution\n");
    printf("Author: LAHTP\n");
    printf("License: Educational/Research Use\n\n");
}

/**
 * @brief Print program usage help information
 * 
 * Displays comprehensive help information including available
 * command-line options and usage examples.
 * 
 * @param program_name Name of the executable for usage examples
 */
void print_help(const char *program_name) {
    if (!program_name) {
        program_name = "arp_detector";
    }
    
    printf("\nCOMMAND LINE OPTIONS:\n");
    printf("============================================\n");
    printf("  -h, --help           Display this help information\n");
    printf("  -l, --lookup         List available network interfaces\n");
    printf("  -i, --interface      Specify interface to monitor\n");
    printf("  -v, --version        Display version information\n");
    printf("============================================\n");
    
    printf("\nUSAGE EXAMPLES:\n");
    printf("  %s -l                    # List interfaces\n", program_name);
    printf("  sudo %s -i eth0          # Monitor eth0 interface\n", program_name);
    printf("  sudo %s -i wlan0         # Monitor wireless interface\n", program_name);
    
    printf("\nIMPORTANT NOTES:\n");
    printf("  • Root privileges required for packet capture\n");
    printf("  • Only use on networks you own or have permission to monitor\n");
    printf("  • Detection threshold: >%d packets in %d seconds\n", 
           PACKET_THRESHOLD, DETECTION_WINDOW);
    printf("  • Press Ctrl+C to stop monitoring\n\n");
    
    exit(EXIT_SUCCESS);
}

/**
 * @brief Convert binary MAC address to formatted string
 * 
 * Takes a 6-byte MAC address and formats it as a human-readable
 * string in the standard colon-separated hexadecimal format.
 * 
 * @param mac 6-byte MAC address array
 * @return Dynamically allocated string in format "XX:XX:XX:XX:XX:XX"
 * @warning Caller must free returned memory to avoid memory leaks
 */
char* format_mac_address(const uint8_t mac[6]) {
    if (!mac) {
        return NULL;
    }
    
    /* Allocate memory for formatted MAC address string */
    char *mac_str = (char*)malloc(MAC_ADDR_LEN * sizeof(char));
    if (!mac_str) {
        fprintf(stderr, "Error: Memory allocation failed for MAC address\n");
        return NULL;
    }
    
    /* Format MAC address as colon-separated hexadecimal */
    snprintf(mac_str, MAC_ADDR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return mac_str;
}

/**
 * @brief Convert binary IP address to formatted string
 * 
 * Takes a 4-byte IP address and formats it as a human-readable
 * string in dotted decimal notation.
 * 
 * @param ip 4-byte IP address array
 * @return Dynamically allocated string in dotted decimal format
 * @warning Caller must free returned memory to avoid memory leaks
 */
char* format_ip_address(const uint8_t ip[4]) {
    if (!ip) {
        return NULL;
    }
    
    /* Allocate memory for formatted IP address string */
    char *ip_str = (char*)malloc(IP_ADDR_LEN * sizeof(char));
    if (!ip_str) {
        fprintf(stderr, "Error: Memory allocation failed for IP address\n");
        return NULL;
    }
    
    /* Format IP address in dotted decimal notation */
    snprintf(ip_str, IP_ADDR_LEN, "%d.%d.%d.%d", 
             ip[0], ip[1], ip[2], ip[3]);
    
    return ip_str;
}

/**
 * @brief Main packet capture and analysis function
 * 
 * This is the core function that performs real-time packet capture
 * and analysis. It opens the specified network interface, captures
 * packets in a continuous loop, filters for ARP packets, and applies
 * the detection algorithm to identify potential spoofing attacks.
 * 
 * Detection Algorithm:
 * - Counts ARP packets within a sliding time window
 * - Resets counter if gap between packets exceeds DETECTION_WINDOW
 * - Triggers alert if packet count exceeds PACKET_THRESHOLD
 * 
 * @param device_name Name of network interface to monitor
 * @return 0 on normal termination (never reached), -1 on error
 */
int sniff_arp_packets(const char *device_name) {
    /* Validate input parameters */
    if (!device_name) {
        fprintf(stderr, "Error: Invalid device name provided\n");
        return -1;
    }
    
    /* Initialize packet capture variables */
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *packet_descriptor = NULL;
    const unsigned char *packet = NULL;
    struct pcap_pkthdr packet_header;
    struct ether_header *ethernet_header = NULL;
    arp_header_t *arp_header = NULL;
    
    /* Detection algorithm variables */
    int packet_counter = 0;
    time_t current_time, last_time = 0;
    long time_difference = 0;
    
    /* Address formatting variables */
    char *sender_mac = NULL, *sender_ip = NULL;
    char *target_mac = NULL, *target_ip = NULL;
    
    printf("Initializing packet capture on interface: %s\n", device_name);
    
    /* Open network interface for packet capture
     * Parameters:
     * - device_name: interface to capture from
     * - BUFSIZ: snapshot length (max bytes per packet)
     * - 0: non-promiscuous mode
     * - 1: timeout in milliseconds
     * - error_buffer: buffer for error messages
     */
    packet_descriptor = pcap_open_live(device_name, BUFSIZ, 0, 1, error_buffer);
    if (!packet_descriptor) {
        fprintf(stderr, "Error: Cannot open interface '%s': %s\n", 
                device_name, error_buffer);
        printf("\nTry one of these available interfaces:\n");
        print_available_interfaces();
        return -1;
    }
    
    printf("Successfully opened interface: %s\n", device_name);
    printf("Monitoring for ARP packets... (Press Ctrl+C to stop)\n");
    printf("Detection parameters: >%d packets in %d seconds = ALERT\n\n", 
           PACKET_THRESHOLD, DETECTION_WINDOW);
    
    /* Main packet capture loop */
    while (1) {
        /* Capture next packet from interface */
        packet = pcap_next(packet_descriptor, &packet_header);
        
        if (!packet) {
            fprintf(stderr, "Warning: Failed to capture packet\n");
            continue; /* Continue instead of exiting */
        }
        
        /* Parse Ethernet header to check packet type */
        ethernet_header = (struct ether_header*)packet;
        
        /* Filter for ARP packets only */
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            /* Update timing information for detection algorithm */
            current_time = time(NULL);
            time_difference = current_time - last_time;
            
            /* Debug information */
            printf("\n[DEBUG] Time: %ld, Diff: %ld seconds, Counter: %d\n",
                   current_time, time_difference, packet_counter);
            
            /* Reset counter if too much time has passed between packets */
            if (time_difference > DETECTION_WINDOW) {
                packet_counter = 0;
                printf("[DEBUG] Counter reset due to time gap\n");
            }
            
            /* Parse ARP header (skip 14-byte Ethernet header) */
            arp_header = (arp_header_t*)(packet + ETHER_HDR_LEN);
            
            /* Display packet information */
            printf("\n=== ARP PACKET CAPTURED ===\n");
            printf("Packet Length: %d bytes\n", packet_header.len);
            printf("Timestamp: %s", ctime((const time_t*)&packet_header.ts.tv_sec));
            printf("Ethernet Header Length: %d bytes\n", ETHER_HDR_LEN);
            
            /* Determine ARP operation type */
            uint16_t operation = ntohs(arp_header->opcode);
            printf("ARP Operation: %s (%d)\n", 
                   (operation == ARP_REQUEST) ? "REQUEST" : "RESPONSE", 
                   operation);
            
            /* Format and display addresses */
            sender_mac = format_mac_address(arp_header->sender_mac);
            sender_ip = format_ip_address(arp_header->sender_ip);
            target_mac = format_mac_address(arp_header->target_mac);
            target_ip = format_ip_address(arp_header->target_ip);
            
            if (sender_mac && sender_ip && target_mac && target_ip) {
                printf("Sender MAC: %s\n", sender_mac);
                printf("Sender IP:  %s\n", sender_ip);
                printf("Target MAC: %s\n", target_mac);
                printf("Target IP:  %s\n", target_ip);
            } else {
                fprintf(stderr, "Error: Failed to format addresses\n");
            }
            
            printf("================================\n");
            
            /* Update detection algorithm state */
            packet_counter++;
            last_time = current_time;
            
            /* Check if threshold exceeded (potential attack detected) */
            if (packet_counter > PACKET_THRESHOLD) {
                if (sender_ip && sender_mac) {
                    alert_spoof(sender_ip, sender_mac);
                }
                
                /* Reset counter after alert to prevent spam */
                packet_counter = 0;
            }
            
            /* Clean up dynamically allocated memory */
            free(sender_mac);
            free(sender_ip);
            free(target_mac);
            free(target_ip);
            
            /* Reset pointers to avoid accidental reuse */
            sender_mac = sender_ip = target_mac = target_ip = NULL;
        }
    }
    
    /* This code is never reached due to infinite loop above */
    /* TODO: Add signal handling for graceful shutdown */
    pcap_close(packet_descriptor);
    return 0;
}

/**
 * @brief Check if required system dependencies are available
 * 
 * Verifies that all required external programs and libraries
 * are installed and accessible on the system.
 * 
 * @return 0 if all dependencies present, -1 otherwise
 */
int check_dependencies(void) {
    printf("Checking system dependencies...\n");
    
    /* Check for libnotify-bin (notify-send command) */
    if (access("/usr/bin/notify-send", F_OK) == -1) {
        fprintf(stderr, "Error: Missing dependency - libnotify-bin\n");
        fprintf(stderr, "Please install with: sudo apt-get install libnotify-bin\n");
        return -1;
    }
    
    printf("✓ All dependencies satisfied\n\n");
    return 0;
}

/**
 * @brief Main program entry point
 * 
 * Handles command-line argument parsing, dependency checking,
 * and delegates to appropriate functions based on user input.
 * 
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on successful execution, -1 on error
 */
int main(int argc, char *argv[]) {
    /* Check system dependencies first */
    if (check_dependencies() != 0) {
        print_version();
        return -1;
    }
    
    /* Handle case with no arguments or help request */
    if (argc < 2 || 
        strcmp("-h", argv[1]) == 0 || 
        strcmp("--help", argv[1]) == 0) {
        print_version();
        print_help(argv[0]);
        return 0; /* print_help() calls exit() */
    }
    
    /* Parse command-line arguments */
    if (strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0) {
        /* Display version information */
        print_version();
        return 0;
        
    } else if (strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0) {
        /* List available network interfaces */
        return print_available_interfaces();
        
    } else if (strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0) {
        /* Start packet capture on specified interface */
        if (argc < 3) {
            fprintf(stderr, "Error: Interface name required after -i option\n");
            printf("Available interfaces:\n");
            print_available_interfaces();
            printf("\nUsage: %s -i <interface_name>\n", argv[0]);
            return -1;
        }
        
        /* Check if running with sufficient privileges */
        if (geteuid() != 0) {
            fprintf(stderr, "Warning: This program requires root privileges for packet capture.\n");
            fprintf(stderr, "Please run with: sudo %s -i %s\n", argv[0], argv[2]);
        }
        
        /* Start monitoring specified interface */
        printf("Starting ARP monitoring on interface: %s\n", argv[2]);
        return sniff_arp_packets(argv[2]);
        
    } else {
        /* Invalid argument provided */
        fprintf(stderr, "Error: Invalid argument '%s'\n", argv[1]);
        print_help(argv[0]);
        return -1;
    }
    
    return 0;
}
