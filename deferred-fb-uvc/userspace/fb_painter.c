#include <fcntl.h>
#include <linux/fb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static void draw_bars_rgb565(uint16_t *base, uint32_t w, uint32_t h, uint32_t stride_px, uint32_t phase)
{
#if 0
    uint32_t y;
    for (y = 0; y < h; y++) {
        uint32_t x;
        uint16_t *row = base + (size_t)y * stride_px;
        for (x = 0; x < w; x++) {
            uint8_t r = (uint8_t)((x + phase) & 0xff);
            uint8_t g = (uint8_t)((y + (phase * 2)) & 0xff);
            uint8_t b = (uint8_t)(((x + y) / 2 + phase * 3) & 0xff);
            uint16_t rgb565 = (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
            row[x] = rgb565;
        }
    }
#else

    uint32_t y;
    for (y = 0; y < h; y++) {
        uint32_t x;
        uint16_t *row = base + (size_t)y * stride_px;
        for (x = 0; x < w; x++) {

            uint8_t r = 0;
            uint8_t g = 0;
            uint8_t b = 0;
            if (phase % 3 == 0)
            {
                r = 0xff;
            }
            else if (phase % 3 == 1)
            {
                g = 0xff;
            }
            else if (phase % 3 == 2)
            {
                b = 0xff;
            }
            uint16_t rgb565 = (uint16_t)(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
            row[x] = rgb565;
        }
    }
#endif
}

int main(int argc, char **argv)
{
    const char *fb_path = argc > 1 ? argv[1] : "/dev/fb0";
    int fd = -1;
    struct fb_var_screeninfo var;
    struct fb_fix_screeninfo fix;
    uint8_t *map = NULL;
    size_t size;
    struct timespec ts = {.tv_sec = 1, .tv_nsec = 33000000L};
    uint32_t phase = 0;

    fd = open(fb_path, O_RDWR);
    if (fd < 0) {
        perror("open fb");
        return 1;
    }

    if (ioctl(fd, FBIOGET_VSCREENINFO, &var) < 0 || ioctl(fd, FBIOGET_FSCREENINFO, &fix) < 0) {
        perror("FBIOGET");
        close(fd);
        return 1;
    }

    if (var.bits_per_pixel != 16) {
        fprintf(stderr, "fb_painter currently expects RGB565 (16bpp), got %u\n", var.bits_per_pixel);
        close(fd);
        return 1;
    }

    size = (size_t)fix.line_length * var.yres;
    map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap fb");
        close(fd);
        return 1;
    }

    printf("painting %ux%u on %s via mmap...\n", var.xres, var.yres, fb_path);
    sleep(1);
    while (1) {
        draw_bars_rgb565((uint16_t *)map, var.xres, var.yres, fix.line_length / 2, phase++);
        nanosleep(&ts, NULL);
    }

    return 0;
}
