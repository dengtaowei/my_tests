#include <stdio.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>

// mknod /dev/m_deferred_io c 247 0

#define BUFFER_SIZE 1024

int main(int argc, const char*argv[])
{
    int fd = open("/dev/m_deferred_io", O_RDWR);
    if (fd < 0)
    {
        printf("err open\n");
        return -1;
    }
    // struct fb_var_screeninfo var;
    // struct fb_fix_screeninfo fix;
    
    // ioctl(fd, FBIOGET_VSCREENINFO, &var);
    // ioctl(fd, FBIOGET_FSCREENINFO, &fix);
    
    /* 映射 framebuffer */
    unsigned char *fb = mmap(NULL, BUFFER_SIZE, 
                    PROT_READ | PROT_WRITE, 
                    MAP_SHARED, fd, 0);

    // fb[0] = 0xff;
    printf("(%s, %s) %d\n", argv[1], argv[2], 128 * atoi(argv[1]) + atoi(argv[2]));
    // fb[128 * atoi(argv[1]) + atoi(argv[2])] = 0xff;
    printf("%02x\n", fb[0]);
    fb[0] = 0xfa;
    printf("%02x\n", fb[0]);
    sleep(1);
    fb[1] = 0xfb;
    printf("%02x\n", fb[1]);
    
    // /* 频繁更新小区域 - 延迟 I/O 会合并这些更新 */
    // for (int i = 0; i < 1000; i++) {
    //     /* 更新一个像素点 */
    //     int x = rand() % 128;
    //     int y = rand() % 64;
    //     fb[y * 128 + x] = 0xFF;  /* 白色像素 */
        
    //     /* 或者更新一个小区域 */
    //     for (int dy = 0; dy < 4; dy++) {
    //         for (int dx = 0; dx < 4; dx++) {
    //             fb[(y+dy) * 128 + (x+dx)] = 0xFF;
    //         }
    //     }
        
    //     usleep(1000);  /* 1ms 延迟，模拟实时更新 */
    // }
    // while (1)
    // {
    //     sleep(1);
    // }
    
    munmap(fb, 4096);
    close(fd);
    return 0;
}