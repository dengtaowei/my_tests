/*
 * 简化的虚拟WiFi驱动 - 专注于基本功能
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/etherdevice.h>
#include <net/mac80211.h>

#define DRV_NAME "simple_virt_wifi"
#define DRV_VERSION "1.0"

MODULE_AUTHOR("H3C AI Assistant");
MODULE_DESCRIPTION("Simple Virtual WiFi Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

/* 驱动私有数据结构 */
struct simple_virt_wifi_priv {
    struct ieee80211_hw *hw;
    struct platform_device *pdev;
    bool running;
};

/* ==================== 硬件操作回调函数 ==================== */

/* TX: 发送数据帧 */
static void simple_virt_wifi_tx(struct ieee80211_hw *hw,
                               struct ieee80211_tx_control *control,
                               struct sk_buff *skb)
{
    /* 虚拟驱动：直接释放skb，模拟发送成功 */
    dev_kfree_skb(skb);
    
    /* 通知mac80211发送完成 */
    ieee80211_tx_status_irqsafe(hw, skb);
}

/* 添加虚拟接口 */
static int simple_virt_wifi_add_interface(struct ieee80211_hw *hw,
                                         struct ieee80211_vif *vif)
{
    printk(KERN_INFO DRV_NAME ": Adding interface type %d\n", vif->type);
    return 0;
}

/* 移除虚拟接口 */
static void simple_virt_wifi_remove_interface(struct ieee80211_hw *hw,
                                             struct ieee80211_vif *vif)
{
    printk(KERN_INFO DRV_NAME ": Removing interface\n");
}

/* 配置接口 */
static int simple_virt_wifi_config(struct ieee80211_hw *hw, u32 changed)
{
    printk(KERN_DEBUG DRV_NAME ": Config changed: 0x%08x\n", changed);
    return 0;
}

/* 开始函数 */
static int simple_virt_wifi_start(struct ieee80211_hw *hw)
{
    printk(KERN_INFO DRV_NAME ": Hardware started\n");
    return 0;
}

/* 停止函数 */
static void simple_virt_wifi_stop(struct ieee80211_hw *hw)
{
    printk(KERN_INFO DRV_NAME ": Hardware stopped\n");
}

/* 配置过滤器 */
static void simple_virt_wifi_configure_filter(struct ieee80211_hw *hw,
                                             unsigned int changed_flags,
                                             unsigned int *total_flags,
                                             u64 multicast)
{
    *total_flags = 0;
    printk(KERN_DEBUG DRV_NAME ": Configure filter: 0x%08x\n", changed_flags);
}

/* 开始扫描 */
static void simple_virt_wifi_sw_scan_start(struct ieee80211_hw *hw,
                                          struct ieee80211_vif *vif,
                                          const u8 *mac_addr)
{
    printk(KERN_INFO DRV_NAME ": Software scan started\n");
}

/* 扫描完成 */
static void simple_virt_wifi_sw_scan_complete(struct ieee80211_hw *hw,
                                             struct ieee80211_vif *vif)
{
    struct cfg80211_scan_info info = {
        .aborted = false,
    };
    
    printk(KERN_INFO DRV_NAME ": Software scan completed\n");
    ieee80211_scan_completed(hw, &info);
}

/* ==================== 定义硬件操作集 ==================== */

static const struct ieee80211_ops simple_virt_wifi_ops = {
    .tx                         = simple_virt_wifi_tx,
    .wake_tx_queue              = ieee80211_handle_wake_tx_queue,
    .start                      = simple_virt_wifi_start,
    .stop                       = simple_virt_wifi_stop,
    .add_interface              = simple_virt_wifi_add_interface,
    .remove_interface           = simple_virt_wifi_remove_interface,
    .config                     = simple_virt_wifi_config,
    .configure_filter           = simple_virt_wifi_configure_filter,
    .sw_scan_start              = simple_virt_wifi_sw_scan_start,
    .sw_scan_complete           = simple_virt_wifi_sw_scan_complete,
};

/* ==================== 平台设备驱动部分 ==================== */

static int simple_virt_wifi_probe(struct platform_device *pdev)
{
    struct ieee80211_hw *hw;
    struct simple_virt_wifi_priv *priv;
    struct wiphy *wiphy;
    int err, i;
    
    printk(KERN_INFO DRV_NAME ": Probing virtual WiFi device\n");
    
    /* 1. 分配IEEE 802.11硬件结构 */
    hw = ieee80211_alloc_hw(sizeof(struct simple_virt_wifi_priv),
                           &simple_virt_wifi_ops);
    if (!hw) {
        printk(KERN_ERR DRV_NAME ": Failed to allocate ieee80211_hw\n");
        return -ENOMEM;
    }

    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    
    /* 获取私有数据指针 */
    priv = hw->priv;
    memset(priv, 0, sizeof(*priv));
    priv->hw = hw;
    priv->pdev = pdev;
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 2. 设置硬件信息 */
    SET_IEEE80211_DEV(hw, &pdev->dev);
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 3. 设置硬件标志 */
    ieee80211_hw_set(hw, SIGNAL_DBM);
    ieee80211_hw_set(hw, SUPPORTS_PS);
    ieee80211_hw_set(hw, PS_NULLFUNC_STACK);
    // ieee80211_hw_set(hw, HAS_RATE_CONTROL);
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 4. 设置支持的接口模式 */
    hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
                                 BIT(NL80211_IFTYPE_AP);
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 5. 设置硬件能力 */
    hw->queues = 4;  /* 必须有这个设置！ */
    hw->extra_tx_headroom = 0;
    hw->max_rates = 4;
    hw->max_rate_tries = 3;
    hw->max_listen_interval = 10;
    
    /* 6. 设置支持的频段 - 必须要有！ */
    struct ieee80211_supported_band *sband;
    
    sband = kzalloc(sizeof(*sband) + 
                    sizeof(struct ieee80211_channel) * 14 +
                    sizeof(struct ieee80211_rate) * 12, GFP_KERNEL);
    if (!sband) {
        err = -ENOMEM;
        goto err_free_hw;
    }
    
    /* 2.4GHz频段 */
    sband->band = NL80211_BAND_2GHZ;
    sband->n_channels = 14;
    sband->n_bitrates = 12;
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    sband->channels = (struct ieee80211_channel *)(sband + 1);
    /* 设置信道（1-14） */
    for (i = 0; i < 14; i++) {
        struct ieee80211_channel *chan = &sband->channels[i];
        
        chan->band = NL80211_BAND_2GHZ;
        chan->center_freq = 2412 + (i * 5);
        chan->hw_value = i + 1;
        chan->max_power = 20;
        
        if (i < 11) {
            chan->flags = IEEE80211_CHAN_NO_HT40;
        }
    }
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 设置支持的速率 */
    struct ieee80211_rate *rates = (struct ieee80211_rate *)(((unsigned char *)(sband + 1)) + sizeof(struct ieee80211_channel) * 14);
    for (i = 0; i < 12; i++) {
        rates[i].bitrate = (i + 1) * 10;
        rates[i].hw_value = i;
        rates[i].flags = IEEE80211_RATE_SHORT_PREAMBLE;
    }
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    sband->bitrates = rates;
    hw->wiphy->bands[NL80211_BAND_2GHZ] = sband;
    
    /* 7. 设置MAC地址 */
    static u8 mac_addr[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(hw->wiphy->perm_addr, mac_addr, ETH_ALEN);
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 8. 设置其他wiphy参数 */
    wiphy = hw->wiphy;
    wiphy->max_scan_ssids = 4;
    wiphy->max_scan_ie_len = 1000;
    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
    wiphy->n_cipher_suites = 0;
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 9. 注册硬件 */
    err = ieee80211_register_hw(hw);
    if (err) {
        printk(KERN_ERR DRV_NAME ": Failed to register ieee80211_hw: %d\n", err);
        goto err_free_sband;
    }
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    /* 10. 保存到设备私有数据 */
    platform_set_drvdata(pdev, hw);
    printk(KERN_INFO DRV_NAME "[%s][%d]\n", __func__, __LINE__);
    printk(KERN_INFO DRV_NAME ": Virtual WiFi device registered successfully\n");
    printk(KERN_INFO DRV_NAME ": MAC address: %pM\n", hw->wiphy->perm_addr);
    
    priv->running = true;
    return 0;
    
err_free_sband:
    kfree(sband);
err_free_hw:
    ieee80211_free_hw(hw);
    return err;
}

static int simple_virt_wifi_remove(struct platform_device *pdev)
{
    struct ieee80211_hw *hw = platform_get_drvdata(pdev);
    
    if (!hw)
        return 0;
    
    printk(KERN_INFO DRV_NAME ": Removing virtual WiFi device\n");
    
    /* 注销硬件 */
    ieee80211_unregister_hw(hw);
    
    /* 释放频段资源 */
    kfree(hw->wiphy->bands[NL80211_BAND_2GHZ]);
    
    /* 释放硬件结构 */
    ieee80211_free_hw(hw);
    
    platform_set_drvdata(pdev, NULL);
    
    printk(KERN_INFO DRV_NAME ": Device removed\n");
    return 0;
}

/* 平台设备定义 */
static struct platform_device simple_virt_wifi_device = {
    .name = DRV_NAME,
    .id = -1,
};

static struct platform_driver simple_virt_wifi_driver = {
    .probe = simple_virt_wifi_probe,
    .remove = simple_virt_wifi_remove,
    .driver = {
        .name = DRV_NAME,
        .owner = THIS_MODULE,
    },
};

/* ==================== 模块初始化和清理 ==================== */

static int __init simple_virt_wifi_init(void)
{
    int ret;
    
    printk(KERN_INFO DRV_NAME ": Initializing module (version %s)\n", DRV_VERSION);
    
    /* 注册平台驱动 */
    ret = platform_driver_register(&simple_virt_wifi_driver);
    if (ret) {
        printk(KERN_ERR DRV_NAME ": Failed to register platform driver: %d\n", ret);
        return ret;
    }
    
    /* 注册平台设备 */
    ret = platform_device_register(&simple_virt_wifi_device);
    if (ret) {
        printk(KERN_ERR DRV_NAME ": Failed to register platform device: %d\n", ret);
        platform_driver_unregister(&simple_virt_wifi_driver);
        return ret;
    }
    
    printk(KERN_INFO DRV_NAME ": Module initialized successfully\n");
    return 0;
}

static void __exit simple_virt_wifi_exit(void)
{
    printk(KERN_INFO DRV_NAME ": Unloading module\n");
    
    platform_device_unregister(&simple_virt_wifi_device);
    platform_driver_unregister(&simple_virt_wifi_driver);
    
    printk(KERN_INFO DRV_NAME ": Module unloaded\n");
}

module_init(simple_virt_wifi_init);
module_exit(simple_virt_wifi_exit);