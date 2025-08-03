#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <arpa/inet.h>

// Translate transport protocol code to string
char* transport_protocol(unsigned int code) {
    switch(code) {
        case 1: return "icmp";
        case 2: return "igmp";
        case 6: return "tcp";
        case 17: return "udp";
        default: return "unknown";
    }
}

int main(int argc, char **argv) {
    int sock, n;
    char buffer[2048];
    unsigned char *iphead, *ethhead;

    // Create a raw socket using PF_PACKET to capture IP packets
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        exit(1);
    }

    // Bind the socket to a specific interface (eth0)
    const char *opt = "eth0";
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(sock);
        exit(1);
    }

    // Enable promiscuous mode on the interface to capture all packets
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, "eth0", IF_NAMESIZE);
    if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
        perror("ioctl get flags");
        close(sock);
        exit(1);
    }
    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("ioctl set flags");
        close(sock);
        exit(1);
    }

    // Attach a BPF filter (e.g., tcpdump 'tcp') to capture only TCP packets
    struct sock_filter BPF_code[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 5, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 6, 0, 0x00000006 },
        { 0x15, 0, 6, 0x0000002c },
        { 0x30, 0, 0, 0x00000036 },
        { 0x15, 3, 4, 0x00000006 },
        { 0x15, 0, 3, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 1, 0x00000006 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 }
    };    
    struct sock_fprog Filter;
    Filter.len = sizeof(BPF_code) / sizeof(BPF_code[0]);
    Filter.filter = BPF_code;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0) {
        perror("setsockopt attach filter");
        close(sock);
        exit(1);
    }

    // Packet capture loop
    while (1) {
        printf("-----------\n");
        n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        printf("%d bytes read\n", n);

        // Basic validation to check minimum packet size for Ethernet + IP + TCP/UDP headers
        if (n < 42) {
            perror("recvfrom()");
            printf("Incomplete packet (errno is %d)\n", errno);
            close(sock);
            exit(0);
        }

        // Print source and destination MAC addresses
        ethhead = buffer;
        printf("Source MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               ethhead[0], ethhead[1], ethhead[2],
               ethhead[3], ethhead[4], ethhead[5]);
        printf("Destination MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               ethhead[6], ethhead[7], ethhead[8],
               ethhead[9], ethhead[10], ethhead[11]);

        iphead = buffer + 14; // Ethernet header is 14 bytes

        // Check for IPv4 without options (first byte = 0x45)
        if (*iphead == 0x45) {
            printf("Source host %d.%d.%d.%d\n",
                   iphead[12], iphead[13], iphead[14], iphead[15]);
            printf("Dest host %d.%d.%d.%d\n",
                   iphead[16], iphead[17], iphead[18], iphead[19]);
            printf("Source,Dest ports %d,%d\n",
                   (iphead[20] << 8) + iphead[21],
                   (iphead[22] << 8) + iphead[23]);
            printf("Layer-4 protocol %s\n", transport_protocol(iphead[9]));
        }
    }
}
