#!/bin/bash

# 加载模块
echo "Loading simple_virt_wifi module..."
sudo insmod simple_virt_wifi.ko

# 等待接口创建
sleep 2

# 查看接口
echo -e "\nNetwork interfaces:"
ip link show | grep swlan

# 使用iw工具测试
echo -e "\nWireless info:"
iw dev

# 扫描网络
echo -e "\nScanning..."
sudo iw dev swlan0 scan

# 尝试连接
echo -e "\nConnecting to SimpleVirtWiFi..."
sudo iw dev swlan0 connect "SimpleVirtWiFi"

# 查看连接状态
echo -e "\nConnection status:"
iw dev swlan0 link

# 查看站点信息
echo -e "\nStation info:"
iw dev swlan0 station dump

# 清理
echo -e "\nCleaning up..."
sudo rmmod simple_virt_wifi

echo "Test completed!"