#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "kfetch.h"

#define DEVICE_PATH "/dev/kfetch"
#define BUFFER_SIZE 1024  // 和 kfech_buf 相同

void print_usage(const char *prog_name) {
    printf("Usage:\n");
    printf("    %s [options]\n", prog_name);
    printf("Options:\n");
    printf("    -a  Show all information\n");
    printf("    -c  Show CPU model name\n");
    printf("    -m  Show memory information\n");
    printf("    -n  Show the number of CPU cores\n");
    printf("    -p  Show the number of processes\n");
    printf("    -r  Show the kernel release information\n");
    printf("    -u  Show how long the system has been running\n");
}

int main(int argc, char *argv[]) {
    int opt;
    int info_mask;
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    info_mask = -1;
    while ((opt = getopt(argc, argv, "acmnpruh")) != -1) {
        // printf("opt = %c \n", opt); // 打印有效選項
        if (info_mask < 0)
            info_mask = 0;
        switch (opt) {
            case 'a':
                info_mask = KFETCH_FULL_INFO; // 全部信息
                break;
            case 'c':
                info_mask |= KFETCH_CPU_MODEL; // CPU 型號
                break;
            case 'm':
                info_mask |= KFETCH_MEM; // 記憶體
                break;
            case 'n':
                info_mask |= KFETCH_NUM_CPUS; // CPU 核心數量
                break;
            case 'p':
                info_mask |= KFETCH_NUM_PROCS; // 進程數量
                break;
            case 'r':
                info_mask |= KFETCH_RELEASE; // 核心版本
                break;
            case 'u':
                info_mask |= KFETCH_UPTIME; // 運行時間
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
        }
    }


    // 寫入信息掩碼
    if (info_mask > 0x3F) {
        fprintf(stderr, "Invalid info_mask value: 0x%x\n", info_mask);
        return EXIT_FAILURE;
    }

    // 打開字符設備
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return EXIT_FAILURE;
    }

    // printf("info_mask befor write = %d \n",info_mask);

    // 如果沒有帶參數，就不更新 module 中的 kfetch_mask
    if(info_mask != -1){
        if (write(fd, &info_mask, sizeof(info_mask)) < 0) {
            perror("Failed to write to device");
            close(fd);
            return EXIT_FAILURE;
        }
    }
   

    // 從設備讀取信息
    bytes_read = read(fd, buffer, 1);
    if (bytes_read < 0) {
        perror("Failed to read from device");
        close(fd);
        return EXIT_FAILURE;
    }

    buffer[bytes_read] = '\0'; // 確保字串結尾
    printf("%s\n", buffer);

    close(fd);
    return EXIT_SUCCESS;
}