
# Packet Sniffer

This is a basic packet sniffer program written in C that uses the `libpcap` library to capture and display basic information about network packets on a specified interface.

## Features

* **Device Listing:** Lists all available network interfaces on the system.
* **Interface Selection:** Allows the user to select a specific network interface to capture packets from.
* **Packet Capture:** Captures the first packet received on the selected interface.
* **Ethernet Header Analysis:** Parses and displays information from the Ethernet header, including:
    * Packet length.
    * Capture timestamp.
    * Ethernet header length (which is always 14 bytes).
    * Ethernet type (identifies the protocol of the payload, e.g., IP or ARP).
    * Destination MAC address.
    * Source MAC address.
* **Network Information:** Retrieves and displays the network address and netmask associated with the selected interface.

## Prerequisites

* **libpcap Development Libraries:** You need to have the `libpcap` development libraries installed on your system. The package name might vary depending on your distribution (e.g., `libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora/CentOS).

	***Debian/Ubuntu***

	```bash
	sudo apt install libpcap
	```
	
* **GCC:** A C compiler like GCC is required to compile the code.
	

## Compilation

1.  Save the provided C code as a `.c` file (e.g., `sniffer.c`).

2.  Open your terminal and navigate to the directory where you saved the file.

3.  Compile the code using GCC, linking against the `libpcap` library:
    ```bash
    gcc sniffer.c -o sniffer -lpcap
    ```

## Running the Application

1.  Run the compiled executable with root privileges (or using `sudo`) because capturing network packets typically requires elevated permissions:
    ```bash
    sudo ./sniffer
    ```

2.  The program will first list the available network interfaces along with a numerical index.

3.  Enter the number corresponding to the interface you want to monitor and press Enter.

4.  The program will then:
    * Display the network address and netmask of the selected interface.
    * Capture the first packet received on that interface.
    * Print the length of the captured packet.
    * Print the timestamp when the packet was received.
    * Print the Ethernet header length.
    * Print the Ethernet type (in hexadecimal and decimal), indicating whether it's an IP packet, an ARP packet, or another type.
    * Print the destination and source MAC addresses in hexadecimal format (colon-separated).

## Explanation of the Code

* **Includes:** The code includes necessary header files for standard input/output, memory allocation, system types, the `libpcap` library, network protocols (IP, Ethernet), error handling, socket programming, address conversion, and time functions.
* **`get_inet()` Function:**
    * Takes the device name and an error buffer as input.
    * Opens the specified network interface in promiscuous mode (captures all packets) using `pcap_open_live()`.
    * Captures the next available packet using `pcap_next()`.
    * If a packet is captured, it prints the packet length and timestamp.
    * It then casts the beginning of the packet data to an `ether_header` structure to access Ethernet header fields.
    * It prints the Ethernet type and identifies if it's an IP (`ETHERTYPE_IP`) or ARP (`ETHERTYPE_ARP`) packet.
    * Finally, it extracts and prints the destination and source MAC addresses.
    * The packet capture descriptor is closed using `pcap_close()`.
* **`get_packet()` Function:**
    * Takes the device name and an error buffer as input.
    * Uses `pcap_lookupnet()` to get the network address and netmask associated with the given interface.
    * Converts the network address and netmask from integer format to human-readable dotted-decimal notation using `inet_ntoa()`.
    * Prints the obtained network address and netmask.
* **`main()` Function:**
    * Declares variables for the device name, error buffer, a list of network interfaces (`pcap_if_t`), a temporary interface pointer, an interface counter, and the user's choice.
    * Uses `pcap_findalldevs()` to get a list of all available network interfaces. If an error occurs, it prints an error message and exits.
    * Iterates through the list of interfaces and prints their index and name to the user.
    * Prompts the user to select an interface by entering its corresponding number.
    * Iterates through the interface list again to find the interface name based on the user's input.
    * If an invalid interface is selected, it prints an error message and frees the interface list.
    * Frees the dynamically allocated list of interfaces using `pcap_freealldevs()`.
    * Calls the `get_packet()` and `get_inet()` functions to retrieve network information and capture and analyze the first packet on the selected interface.
    * Returns 0 to indicate successful execution.

## Important Notes

* **Permissions:** Running this program requires root or `sudo` privileges to capture network traffic.
* **First Packet Only:** This program only captures and analyzes the *first* packet received after selecting the interface. To continuously capture packets, you would need to use a loop with `pcap_next()` or `pcap_loop()`.
* **Error Handling:** The error handling in this basic example is limited. In a more robust application, you would want to handle errors more comprehensively.
* **Packet Interpretation:** This program only examines the Ethernet header. To analyze the data within IP, TCP, UDP, or other protocols, you would need to add more code to parse the subsequent layers of the network packet.
