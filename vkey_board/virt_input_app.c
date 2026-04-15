#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/input.h>
#include <sys/time.h>
#include <time.h>

// 按键名称到键值的映射结构
struct key_mapping {
    const char *name;
    int value;
};

// 常见按键映射表
static struct key_mapping key_map[] = {
    {"KEY_ESC", KEY_ESC},
    {"KEY_1", KEY_1},
    {"KEY_2", KEY_2},
    {"KEY_3", KEY_3},
    {"KEY_4", KEY_4},
    {"KEY_5", KEY_5},
    {"KEY_6", KEY_6},
    {"KEY_7", KEY_7},
    {"KEY_8", KEY_8},
    {"KEY_9", KEY_9},
    {"KEY_0", KEY_0},
    {"KEY_Q", KEY_Q},
    {"KEY_W", KEY_W},
    {"KEY_E", KEY_E},
    {"KEY_R", KEY_R},
    {"KEY_T", KEY_T},
    {"KEY_Y", KEY_Y},
    {"KEY_U", KEY_U},
    {"KEY_I", KEY_I},
    {"KEY_O", KEY_O},
    {"KEY_P", KEY_P},
    {"KEY_A", KEY_A},
    {"KEY_S", KEY_S},
    {"KEY_D", KEY_D},
    {"KEY_F", KEY_F},
    {"KEY_G", KEY_G},
    {"KEY_H", KEY_H},
    {"KEY_J", KEY_J},
    {"KEY_K", KEY_K},
    {"KEY_L", KEY_L},
    {"KEY_Z", KEY_Z},
    {"KEY_X", KEY_X},
    {"KEY_C", KEY_C},
    {"KEY_V", KEY_V},
    {"KEY_B", KEY_B},
    {"KEY_N", KEY_N},
    {"KEY_M", KEY_M},
    {"KEY_ENTER", KEY_ENTER},
    {"KEY_SPACE", KEY_SPACE},
    {"KEY_BACKSPACE", KEY_BACKSPACE},
    {"KEY_TAB", KEY_TAB},
    {"KEY_CAPSLOCK", KEY_CAPSLOCK},
    {"KEY_LEFTSHIFT", KEY_LEFTSHIFT},
    {"KEY_RIGHTSHIFT", KEY_RIGHTSHIFT},
    {"KEY_LEFTCTRL", KEY_LEFTCTRL},
    {"KEY_RIGHTCTRL", KEY_RIGHTCTRL},
    {"KEY_LEFTALT", KEY_LEFTALT},
    {"KEY_RIGHTALT", KEY_RIGHTALT},
    {"KEY_LEFTMETA", KEY_LEFTMETA},
    {"KEY_RIGHTMETA", KEY_RIGHTMETA},
    {"KEY_UP", KEY_UP},
    {"KEY_DOWN", KEY_DOWN},
    {"KEY_LEFT", KEY_LEFT},
    {"KEY_RIGHT", KEY_RIGHT},
    {"KEY_F1", KEY_F1},
    {"KEY_F2", KEY_F2},
    {"KEY_F3", KEY_F3},
    {"KEY_F4", KEY_F4},
    {"KEY_F5", KEY_F5},
    {"KEY_F6", KEY_F6},
    {"KEY_F7", KEY_F7},
    {"KEY_F8", KEY_F8},
    {"KEY_F9", KEY_F9},
    {"KEY_F10", KEY_F10},
    {"KEY_F11", KEY_F11},
    {"KEY_F12", KEY_F12},
    {NULL, 0}  // 结束标记
};

// 将按键名称转换为键值
int key_name_to_value(const char *key_name) {
    for (int i = 0; key_map[i].name != NULL; i++) {
        if (strcmp(key_map[i].name, key_name) == 0) {
            return key_map[i].value;
        }
    }
    
    // 如果没有找到，尝试直接解析为数字
    char *endptr;
    long value = strtol(key_name, &endptr, 0);
    if (*endptr == '\0') {
        return (int)value;
    }
    
    return -1;  // 未找到
}

// 获取当前时间戳
void get_current_time(struct timeval *tv) {
    gettimeofday(tv, NULL);
}

// 打印使用说明
void print_usage(const char *prog_name) {
    printf("Usage: %s <KEY_NAME> <STATE>\n", prog_name);
    printf("  KEY_NAME: 按键名称，如 KEY_A, KEY_ENTER 等\n");
    printf("  STATE:    按键状态，1=按下，0=释放\n\n");
    printf("Examples:\n");
    printf("  %s KEY_A 1      # 模拟按下 A 键\n", prog_name);
    printf("  %s KEY_A 0      # 模拟释放 A 键\n", prog_name);
    printf("  %s KEY_ENTER 1  # 模拟按下回车键\n", prog_name);
    printf("\n可用按键示例:\n");
    for (int i = 0; key_map[i].name != NULL && i < 20; i++) {
        printf("  %s", key_map[i].name);
        if ((i + 1) % 5 == 0) printf("\n");
        else printf("\t");
    }
    printf("  ... 更多按键请查看源码\n");
}

int main(int argc, char *argv[]) {
    int fd;
    ssize_t ret;
    struct input_event ev;
    struct timeval tv;
    
    // 检查参数数量
    if (argc != 3) {
        fprintf(stderr, "错误: 参数数量不正确\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // 解析按键名称
    const char *key_name = argv[1];
    int key_value = key_name_to_value(key_name);
    if (key_value < 0) {
        fprintf(stderr, "错误: 无效的按键名称 '%s'\n", key_name);
        printf("请使用以下格式的按键名称:\n");
        for (int i = 0; key_map[i].name != NULL && i < 10; i++) {
            printf("  %s\n", key_map[i].name);
        }
        return EXIT_FAILURE;
    }
    
    // 解析按键状态
    char *endptr;
    long state = strtol(argv[2], &endptr, 10);
    if (*endptr != '\0' || (state != 0 && state != 1)) {
        fprintf(stderr, "错误: 无效的按键状态 '%s'\n", argv[2]);
        fprintf(stderr, "按键状态必须是 0 (释放) 或 1 (按下)\n");
        return EXIT_FAILURE;
    }
    
    // 打开输入设备
    fd = open("/dev/virt_input", O_WRONLY);
    if (fd < 0) {
        perror("错误: 无法打开 /dev/virt_input");
        fprintf(stderr, "请确保:\n");
        fprintf(stderr, "1. 驱动程序已加载并创建了 /dev/virt_input 设备\n");
        fprintf(stderr, "2. 当前用户有写入权限\n");
        fprintf(stderr, "3. 设备节点存在 (ls -l /dev/virt_input)\n");
        return EXIT_FAILURE;
    }
    
    // 获取当前时间
    get_current_time(&tv);
    
    // 构造输入事件
    memset(&ev, 0, sizeof(ev));
    
    // 设置时间戳
    ev.time.tv_sec = tv.tv_sec;
    ev.time.tv_usec = tv.tv_usec;
    
    // 设置事件类型为按键事件
    ev.type = EV_KEY;
    
    // 设置按键码
    ev.code = key_value;
    
    // 设置按键状态
    ev.value = (int)state;
    
    printf("发送按键事件:\n");
    printf("  按键: %s (code=%d)\n", key_name, key_value);
    printf("  状态: %s\n", state ? "按下" : "释放");
    printf("  时间戳: %ld.%06ld\n", ev.time.tv_sec, ev.time.tv_usec);
    
    // 发送事件到驱动程序
    ret = write(fd, &ev, sizeof(ev));
    if (ret != sizeof(ev)) {
        perror("错误: 写入设备失败");
        close(fd);
        return EXIT_FAILURE;
    }
    
    printf("事件发送成功!\n");
    
    // 关闭设备
    close(fd);
    
    return EXIT_SUCCESS;
}