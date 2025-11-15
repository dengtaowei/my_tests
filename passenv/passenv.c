#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    setenv("STA_MAC", "00:aa:bb:01:23:45", 1);      // 设置环境变量
    setenv("TIME", "2025-11-15 20:16", 1);

    system("./script.sh");            // 脚本中可直接访问环境变量

    return 0;
}