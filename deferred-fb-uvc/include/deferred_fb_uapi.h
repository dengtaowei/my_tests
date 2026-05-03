#ifndef DEFERRED_FB_UAPI_H
#define DEFERRED_FB_UAPI_H

#include <linux/types.h>

struct deferred_fb_usb_frame_hdr {
    __u32 magic;
    __u32 seq;
    __u32 width;
    __u32 height;
    __u32 bpp;
    __u32 x1;
    __u32 y1;
    __u32 x2;
    __u32 y2;
    __u32 payload_size;
};

#define DEFERRED_FB_USB_MAGIC 0x31424644U /* "DFB1" */

#endif
