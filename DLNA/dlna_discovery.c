#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#define SSDP_PORT 1900
#define SSDP_GROUP "239.255.255.250"
#define BUFFER_SIZE 1024
#define DISCOVERY_INTERVAL 3  // 3秒发送间隔
#define RESPONSE_TIMEOUT 3    // 3秒接收超时

void send_ssdp_discovery(int sockfd) {
    const char *discovery_msg = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n";
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_GROUP, &addr.sin_addr);
    
    if (sendto(sockfd, discovery_msg, strlen(discovery_msg), 0, 
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto failed");
    }
    
    time_t now;
    time(&now);
    printf("[%.24s] Discovery message sent\n", ctime(&now));
}

void parse_ssdp_response(const char *response, struct sockaddr_in *sender_addr) {
    char *location = strstr(response, "LOCATION:");
    if (location) {
        location += strlen("LOCATION:");
        while (*location == ' ' || *location == '\t') location++;
        
        char *end = strchr(location, '\r');
        if (end) *end = '\0';
        
        time_t now;
        time(&now);
        printf("[%.24s] Device found at: %s (from %s)\n", 
               ctime(&now), location, inet_ntoa(sender_addr->sin_addr));
    }
}

int setup_socket() {
    // 创建UDP套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 设置套接字选项允许广播
    int broadcast = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("setsockopt (SO_BROADCAST) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // 设置接收超时
    struct timeval tv;
    tv.tv_sec = RESPONSE_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt (SO_RCVTIMEO) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // 绑定到任意可用端口
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0; // 让系统选择端口
    
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // 加入多播组
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(SSDP_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (IP_ADD_MEMBERSHIP) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    return sockfd;
}

int main() {
    int sockfd = setup_socket();
    char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    
    printf("DLNA Device Discovery started (sending every %d seconds)...\n", DISCOVERY_INTERVAL);
    
    while (1) {
        // 发送发现请求
        send_ssdp_discovery(sockfd);
        
        // 接收响应
        time_t start_time;
        time(&start_time);
        
        while (1) {
            ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0, 
                                       (struct sockaddr *)&sender_addr, &sender_len);
            
            if (recv_len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // 超时，结束本轮接收
                    break;
                } else {
                    perror("recvfrom failed");
                    break;
                }
            }
            
            buffer[recv_len] = '\0';
            parse_ssdp_response(buffer, &sender_addr);
            
            // 检查是否已经超过3秒
            time_t now;
            time(&now);
            if (difftime(now, start_time) >= RESPONSE_TIMEOUT) {
                break;
            }
        }
        
        // 等待直到距离上次发送满3秒
        time_t now;
        time(&now);
        double elapsed = difftime(now, start_time);
        
        if (elapsed < DISCOVERY_INTERVAL) {
            unsigned int sleep_time = (unsigned int)(DISCOVERY_INTERVAL - elapsed);
            sleep(sleep_time);
        }
    }
    
    close(sockfd);
    return 0;
}