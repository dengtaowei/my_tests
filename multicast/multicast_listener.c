#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>

#define BUFSIZE 1024

// 根据接口名称获取其 IPv4 地址
in_addr_t get_interface_ip(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket() failed");
        return INADDR_NONE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR) failed");
        close(fd);
        return INADDR_NONE;
    }

    close(fd);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s -a <multicast_address> -p <port> [-i <interface>]\n", progname);
    fprintf(stderr, "Example: %s -a 239.1.2.3 -p 1234 -i eth0\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int opt;
    char *mcast_addr = NULL;
    char *iface = NULL;
    int port = 0;

    while ((opt = getopt(argc, argv, "a:p:i:")) != -1) {
        switch (opt) {
            case 'a': mcast_addr = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'i': iface = optarg; break;
            default: print_usage(argv[0]);
        }
    }

    if (!mcast_addr || port <= 0) {
        print_usage(argv[0]);
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, mcast_addr, &mreq.imr_multiaddr) <= 0) {
        perror("inet_pton() failed for multicast address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (iface) {
        mreq.imr_interface.s_addr = get_interface_ip(iface);
        if (mreq.imr_interface.s_addr == INADDR_NONE) {
            fprintf(stderr, "Failed to get IP address for interface %s\n", iface);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(IP_ADD_MEMBERSHIP) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Joined IPv4 multicast group %s:%d on %s \n",
           mcast_addr, port, iface ? iface : "default");

    char buf[BUFSIZE];
    printf("Listening for multicast data...\n");
    while (1) {
        struct sockaddr_in sender_addr;
        socklen_t sender_len = sizeof(sender_addr);
        
        ssize_t recv_len = recvfrom(sockfd, buf, BUFSIZE, 0, 
                                   (struct sockaddr *)&sender_addr, &sender_len);
        if (recv_len < 0) {
            perror("recvfrom() failed");
            break;
        }

        // 打印发送者信息
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
        printf("Received %zd bytes from %s:%d: %.*s\n", 
               recv_len, 
               sender_ip, 
               ntohs(sender_addr.sin_port),
               (int)recv_len, 
               buf);
    }

    close(sockfd);
    return 0;
}