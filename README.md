# ARP Spoof Detector
[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language)) [![Platform](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org/) [![Version](https://img.shields.io/badge/version-0.1-orange.svg)](https://github.com/yourusername/arp-spoof-detector/releases)

A professional network security tool written in C that monitors ARP (Address Resolution Protocol) traffic to detect potential ARP spoofing attacks in real-time. This tool uses libpcap for packet capture and provides comprehensive monitoring capabilities for network administrators and security professionals.

## Features

-   **Real-time ARP Monitoring** - Continuous packet capture and analysis
-   **Spoofing Detection Algorithm** - Frequency-based attack detection
-   **Professional Logging** - Detailed packet information and timestamps
-   **Interface Discovery** - Automatic detection of available network interfaces
-   **Memory Safe** - Proper memory management and leak prevention
-   **Root Privilege Checking** - Security validation for packet capture
-   **Cross-platform** - Compatible with Linux distributions

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Command Line Options](#command-line-options)
- [Examples](#examples)
- [Security Considerations](#security-considerations)
- [Acknowledgments](#acknowledgments)


## Installation

### Prerequisites

Before compiling, ensure you have the following dependencies installed:

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev libnotify-bin

```

#### CentOS/RHEL/Fedora

```bash
sudo yum install gcc libpcap-devel libnotify
# or for newer versions
sudo dnf install gcc libpcap-devel libnotify

```

#### Arch Linux

```bash
sudo pacman -S gcc libpcap libnotify

```

### Compilation

1.  Clone the repository:

```bash
git clone https://github.com/yourusername/arp-spoof-detector.git
cd arp-spoof-detector

```

2.  Compile the program:

```bash
gcc -o arp_detector arp_detector.c -lpcap

```

3.  Make executable:

```bash
chmod +x arp_detector

```

### Alternative Build Options

**Debug build:**

```bash
gcc -g -DDEBUG -o arp_detector arp_detector.c -lpcap

```

**Optimized build:**

```bash
gcc -O2 -o arp_detector arp_detector.c -lpcap

```

## Usage

### Basic Usage

```bash
# List available network interfaces
./arp_detector -l

# Monitor specific interface (requires root)
sudo ./arp_detector -i eth0

# Show help information
./arp_detector -h

# Display version information
./arp_detector -v

```

### Important Notes

 **Root privileges are required** for packet capture operations  
 **Only use on networks you own** or have explicit permission to monitor  
 **Educational/Research purposes** - ensure compliance with local laws

## How It Works

### Detection Algorithm

The ARP Spoof Detector uses a frequency-based detection method:

1.  **Packet Capture**: Monitors specified network interface for ARP packets
2.  **Time Window Analysis**: Counts packets within a 20-second sliding window
3.  **Threshold Detection**: Triggers alert when >10 packets detected in window
4.  **Alert Generation**: Displays detailed information about potential attacks

### ARP Spoofing Overview

ARP spoofing is a type of attack where malicious actors send falsified ARP messages over a local network, linking their MAC address with the IP address of a legitimate device. This can lead to:

-   Man-in-the-middle attacks
-   Traffic interception
-   Network disruption
-   Data theft

### Detection Metrics
| Metric | Value | Description |
| :------- | :------: | -------: |
| Time Window | 20 seconds | Packet counting interval |
| Packet Threshold | 10 packets | Alert trigger point |
| Reset Behavior | Automatic | Counter resets after time gap |

## Command Line Options
| Option | Long Form | Description |
| :------- | :------: | -------: |
| `-h` | `--help` | Display help information and usage examples |
| `-l`| `--lookup` | List all available network interfaces |
| `-i <interface>` | `--interface <interface>` | Specify network interface to monitor|
|`-v`|`--version`|Show version and program information|

## Examples

### 1. List Network Interfaces

```bash
$ ./arp_detector -l

Available Network Interfaces:
============================================
#1: lo (Loopback)
#2: eth0 (Ethernet)
#3: wlan0 (Wireless)
============================================
Total interfaces found: 3

```

### 2. Monitor Ethernet Interface

```bash
$ sudo ./arp_detector -i eth0

Initializing packet capture on interface: eth0
Successfully opened interface: eth0
Monitoring for ARP packets... (Press Ctrl+C to stop)
Detection parameters: >10 packets in 20 seconds = ALERT

=== ARP PACKET CAPTURED ===
Packet Length: 42 bytes
Timestamp: Wed Aug 16 10:30:56 2023
ARP Operation: REQUEST (1)
Sender MAC: 00:1B:44:11:3A:B7
Sender IP:  192.168.1.100
Target MAC: 00:00:00:00:00:00
Target IP:  192.168.1.1
================================

```

### 3. Detection Alert Example

```bash
[Wed Aug 16 10:31:15 2023] SECURITY ALERT: Potential ARP Spoofing Detected!
Suspected Attacker - IP: 192.168.1.100, MAC: 00:1B:44:11:3A:B7
Recommendation: Investigate network traffic immediately.

```

## Security Considerations

### Ethical Usage

-    **Use only on your own networks**
-   **Obtain explicit permission** before monitoring
-   **Comply with local laws** and regulations
-   **Respect privacy** and data protection rules

### Limitations

-   **Detection Method**: Simple frequency-based (may have false positives)
-   **No Active Protection**: Detection only, no prevention capabilities
-   **Network Segment**: Can only monitor local network segment
-   **Sophisticated Attacks**: May not detect advanced evasion techniques

### Recommended Best Practices

1.  **Regular Monitoring**: Run during suspicious network activity
2.  **Baseline Establishment**: Understand normal ARP traffic patterns
3.  **Incident Response**: Have procedures for detected attacks
4.  **Log Analysis**: Review captured data for patterns
5.  **Network Segmentation**: Limit ARP spoofing impact

## Technical Details

### System Requirements

-   **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, etc.)
-   **Architecture**: x86_64, ARM64
-   **Memory**: Minimal (< 10MB during operation)
-   **Network**: Raw socket access capability

### Dependencies

-   **libpcap**: Packet capture library
-   **libnotify-bin**: Desktop notifications (optional)
-   **gcc**: GNU Compiler Collection

### File Structure

```
arp-spoof-detector/
├── README.md              # This file
├── arp_detector.c         # Main source code
```

## Troubleshooting

### Common Issues

**Permission Denied**

```bash
Error: Cannot open interface 'eth0': Operation not permitted

```

**Solution**: Run with sudo privileges

**Interface Not Found**

```bash
Error: Cannot open interface 'eth1': No such device exists

```

**Solution**: Use `./arp_detector -l` to list available interfaces

**Missing Dependencies**

```bash
Error: Missing dependency - libnotify-bin

```

**Solution**: Install required packages using your distribution's package manager

### Debug Mode

Compile with debug flags for additional information:

```bash
gcc -g -DDEBUG -o arp_detector arp_detector.c -lpcap

```

## Contributing

We welcome contributions! Please follow these guidelines:

### How to Contribute

1.  Fork the repository
2.  Create a feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

### Code Style

-   Follow existing code formatting
-   Add comprehensive comments
-   Include function documentation
-   Test on multiple Linux distributions

### Bug Reports

Please include:

-   Operating system and version
-   Compilation method used
-   Complete error messages
-   Steps to reproduce

### Feature Requests

-   Describe the use case
-   Explain the benefit
-   Consider security implications

## Acknowledgments

-   **libpcap developers** - For the excellent packet capture library
-   **Network security community** - For research on ARP spoofing detection
-   **Open source contributors** - For inspiration and code examples

## Additional Resources

### Learning Resources

-   [RFC 826 - Address Resolution Protocol](https://tools.ietf.org/html/rfc826)
-   [Wireshark ARP Analysis](https://www.wireshark.org/)
-   [Network Security Fundamentals](https://www.sans.org/)

### Related Tools

-   **arpspoof** - Active ARP spoofing tool
-   **ettercap** - Comprehensive network security suite
-   **Wireshark** - Network protocol analyzer
-   **tcpdump** - Command-line packet analyzer

### Professional References

-   [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
-   [OWASP Network Security](https://owasp.org/)
-   [SANS Network Security](https://www.sans.org/)

----------

**If you find this tool useful, please consider giving it a star!**

**Questions or suggestions? Open an issue or contact the maintainer.**

**Remember: Use responsibly and ethically!**
