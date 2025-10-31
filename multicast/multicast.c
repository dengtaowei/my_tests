#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void print_usage(const char *prog_name) {
    printf("Usage: %s <multicast_ip> <port>\n", prog_name);
    printf("Example: %s 239.1.1.5 12345\n", prog_name);
}

int main(int argc, char *argv[]) {
    // 检查参数
    if (argc != 3) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *multicast_ip = argv[1];
    int port = atoi(argv[2]);

    // 验证组播地址有效性
    struct in_addr addr;
    if (inet_pton(AF_INET, multicast_ip, &addr) <= 0) {
        fprintf(stderr, "Invalid multicast IP address\n");
        exit(EXIT_FAILURE);
    }

    // 检查是否为合法的组播地址 (224.0.0.0 - 239.255.255.255)
    unsigned char first_byte = *(unsigned char*)&addr.s_addr;
    if (first_byte < 224 || first_byte > 239) {
        fprintf(stderr, "Error: %s is not a valid multicast address (must be 224.0.0.0 - 239.255.255.255)\n", multicast_ip);
        exit(EXIT_FAILURE);
    }

    // 1. 创建套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. 设置组播TTL
    unsigned char ttl = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IP_MULTICAST_TTL)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 3. 设置目标地址
    struct sockaddr_in multicast_addr = {0};
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(port);
    inet_pton(AF_INET, multicast_ip, &multicast_addr.sin_addr);

    printf("Sending multicast packets to %s:%d\n", multicast_ip, port);
    printf("Press Ctrl+C to stop...\n");

    // 4. 发送数据
    const char *message = "Hello Multicast World!";
    while (1) {
        if (sendto(sockfd, message, strlen(message), 0,
                  (struct sockaddr*)&multicast_addr, sizeof(multicast_addr)) < 0) {
            perror("sendto failed");
            break;
        }
        printf("Sent: %s\n", message);
        sleep(1);
    }

    close(sockfd);
    return 0;
}