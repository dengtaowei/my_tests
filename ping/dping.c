#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define PACKET_SIZE 64
#define DEFAULT_TIMEOUT 5
#define DEFAULT_INTERVAL 1
#define DEFAULT_COUNT 65536

int timeout = DEFAULT_TIMEOUT;  // 超时时间（秒）
int interval = DEFAULT_INTERVAL; // 发包间隔（秒）
int count = DEFAULT_COUNT;      // 发送次数
char *target = NULL;           // 目标地址


// ICMP头部结构
struct icmp_header
{
    uint8_t type;      // 类型
    uint8_t code;      // 代码
    uint16_t checksum; // 校验和
    uint16_t id;       // 标识符
    uint16_t seq;      // 序列号
};

// 全局变量
int sockfd;
int pid;
int transmitted = 0;
int received = 0;

// 计算校验和
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 发送ICMP回显请求
void send_packet(struct sockaddr_in *dest_addr, int seq)
{
    char packet[PACKET_SIZE];
    struct icmp_header *icmp = (struct icmp_header *)packet;

    // 填充ICMP头部
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->id = htons(pid);
    icmp->seq = htons(seq);

    // 填充数据部分（时间戳）
    struct timeval *tv = (struct timeval *)(packet + sizeof(struct icmp_header));
    gettimeofday(tv, NULL);

    // 计算校验和
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, sizeof(packet));

    // 发送数据包
    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr *)dest_addr, sizeof(*dest_addr)) <= 0)
    {
        perror("sendto error");
    }

    transmitted++;
}

// 接收ICMP回显回复
int recv_packet(int seq, struct sockaddr_in *from, int timeout)
{
    fd_set readfds;
    struct timeval tv;
    char packet[PACKET_SIZE + 256]; // 额外空间存放IP头部
    struct ip *ip_hdr;
    struct icmp_header *icmp;
    int ret;
    socklen_t from_len = sizeof(*from);
    int ip_hdr_len;

    // 设置select超时
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    while (1)
    {
        // 等待数据到达
        ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0)
        {
            return -1; // 超时或无数据
        }

        // 接收数据包
        ret = recvfrom(sockfd, packet, sizeof(packet), 0,
                       (struct sockaddr *)from, &from_len);
        if (ret <= 0)
        {
            return -1;
        }

        // 解析IP头部
        ip_hdr = (struct ip *)packet;
        ip_hdr_len = ip_hdr->ip_hl * 4;

        // 检查是否是ICMP回显回复
        if (ret < ip_hdr_len + ICMP_MINLEN)
        {
            return -1;
        }

        icmp = (struct icmp_header *)(packet + ip_hdr_len);

        // 验证是否是我们的回显回复
        // printf("type: %d, code: %d, id: %d, seq: %d\n", icmp->type, icmp->code,
        //     ntohs(icmp->id), ntohs(icmp->seq));

        if (icmp->type != ICMP_ECHOREPLY ||
            icmp->code != 0 ||
            ntohs(icmp->id) != pid ||
            ntohs(icmp->seq) != seq)
        {
            continue;
        }
        else
        {
            break;
        }
    }

    // 计算往返时间
    struct timeval *tv_send = (struct timeval *)((char *)icmp + sizeof(struct icmp_header));
    struct timeval tv_recv;
    gettimeofday(&tv_recv, NULL);

    double rtt = (tv_recv.tv_sec - tv_send->tv_sec) * 1000.0 +
                 (tv_recv.tv_usec - tv_send->tv_usec) / 1000.0;

    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
           ret - ip_hdr_len,
           inet_ntoa(from->sin_addr),
           seq,
           ip_hdr->ip_ttl,
           rtt);

    received++;
    return 0;
}

// 信号处理函数
void sigint_handler(int sig)
{
    printf("\n--- Ping statistics ---\n");
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
           transmitted, received,
           ((transmitted - received) / (float)transmitted) * 100.0);
    close(sockfd);
    exit(0);
}

// 打印使用帮助
void print_usage(char *prog_name) {
    printf("Usage: %s [options] <hostname/IP>\n", prog_name);
    printf("Options:\n");
    printf("  -c count     Number of packets to send (default: %d)\n", DEFAULT_COUNT);
    printf("  -i interval  Interval between packets in seconds (default: %d)\n", DEFAULT_INTERVAL);
    printf("  -W timeout   Time to wait for a reply in seconds (default: %d)\n", DEFAULT_TIMEOUT);
    printf("  -h           Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -c 10 -i 2 -W 3 google.com\n", prog_name);
}

// 解析命令行参数
int parse_args(int argc, char *argv[]) {
    int opt;
    
    while ((opt = getopt(argc, argv, "c:i:W:h")) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                if (count <= 0) {
                    fprintf(stderr, "Error: Count must be positive\n");
                    return -1;
                }
                break;
                
            case 'i':
                interval = atoi(optarg);
                if (interval <= 0) {
                    fprintf(stderr, "Error: Interval must be positive\n");
                    return -1;
                }
                break;
                
            case 'W':
                timeout = atoi(optarg);
                if (timeout <= 0) {
                    fprintf(stderr, "Error: Timeout must be positive\n");
                    return -1;
                }
                break;
                
            case 'h':
                print_usage(argv[0]);
                exit(0);
                
            default:
                fprintf(stderr, "Unknown option: -%c\n", opt);
                return -1;
        }
    }
    
    // 获取目标地址
    if (optind >= argc) {
        fprintf(stderr, "Error: Target address is required\n");
        return -1;
    }
    
    target = argv[optind];
    
    // 验证参数合理性
    if (interval < 0.2) {
        printf("Warning: Very short interval (<0.2s) may cause issues\n");
    }
    
    if (timeout < 1) {
        printf("Warning: Very short timeout (<1s) may cause false timeouts\n");
    }
    
    return 0;
}

int main(int argc, char *argv[]) {

    // 解析命令行参数
    if (parse_args(argc, argv) != 0) {
        fprintf(stderr, "Use -h for help\n");
        exit(1);
    }

    struct hostent *host;
    struct sockaddr_in dest_addr;

    // 解析主机名或IP地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    // 检查是否是IP地址
    if (inet_aton(target, &dest_addr.sin_addr) == 0)
    {
        // 不是IP地址，尝试解析主机名
        host = gethostbyname(argv[1]);
        if (host == NULL)
        {
            herror("gethostbyname error");
            exit(1);
        }
        memcpy(&dest_addr.sin_addr, host->h_addr, host->h_length);
    }

    // 获取进程ID用于ICMP标识符
    pid = getpid() & 0xFFFF;

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror("socket error");
        if (errno == EPERM)
        {
            fprintf(stderr, "Note: This program requires root privileges to create raw sockets.\n");
        }
        exit(1);
    }

    // 设置超时
    struct timeval tv = {timeout, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // 注册信号处理
    signal(SIGINT, sigint_handler);

    printf("PING %s (%s): %ld data bytes\n",
           target, inet_ntoa(dest_addr.sin_addr), PACKET_SIZE - sizeof(struct icmp_header));

    // 主循环：发送和接收数据包
    for (int seq = 1; seq <= count; seq++)
    {
        send_packet(&dest_addr, seq);

        struct sockaddr_in from_addr;
        if (recv_packet(seq, &from_addr, timeout) < 0)
        {
            printf("Request timeout for icmp_seq %d\n", seq);
        }

        // 等待1秒再发送下一个包（模拟标准ping行为）
        if (seq < count)
        {
            sleep(interval);
        }
    }

    // 打印统计信息
    sigint_handler(0);

    return 0;
}