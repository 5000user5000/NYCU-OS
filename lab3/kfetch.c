#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/sched/signal.h> // for signal_struct and for_each_process

#define DEVICE_NAME "kfetch"

// 全域變數
static dev_t dev_number;
static struct cdev kfetch_cdev;
static struct class *kfetch_class;
static char kfetch_buf[512]; // 用來存儲返回給使用者的資訊
static int info_mask = 0x3F; // 預設顯示所有資訊

// 定義互斥鎖
DEFINE_MUTEX(kfetch_mutex);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module to fetch system information");

// open 函數
static int kfetch_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "kfetch: device opened\n");
    return 0;
}

// release 函數
static int kfetch_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "kfetch: device closed\n");
    return 0;
}

// read 函數
static ssize_t kfetch_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    struct sysinfo info;
    struct timespec64 uptime;
    unsigned long totalram, freeram;
    size_t written = 0;
    int process_count = 0;

    // 嘗試取得鎖
    if (!mutex_trylock(&kfetch_mutex)) {
        printk(KERN_WARNING "kfetch: device is busy\n");
        return -EBUSY;
    }

    // 清空緩衝區
    memset(kfetch_buf, 0, sizeof(kfetch_buf));

    // Kernel version
    if (info_mask & (1 << 0)) {
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "Kernel: %s\n", utsname()->release);
    }

    // CPU cores
    if (info_mask & (1 << 1)) {
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "CPUs: %d / %d\n", num_online_cpus(), num_possible_cpus());
    }

    // CPU model
    if (info_mask & (1 << 2)) {
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "CPU Model: (fetch manually from /proc/cpuinfo)\n");
    }

    // Memory information
    if (info_mask & (1 << 3)) {
        si_meminfo(&info);
        totalram = (info.totalram * info.mem_unit) >> 20; // 轉換為 MB
        freeram = (info.freeram * info.mem_unit) >> 20;
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "Mem: %luMB / %luMB\n", freeram, totalram);
    }

    // Uptime
    if (info_mask & (1 << 4)) {
        ktime_get_boottime_ts64(&uptime);
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "Uptime: %lld minutes\n", uptime.tv_sec / 60);
    }

    // Number of processes
    if (info_mask & (1 << 5)) {
        struct task_struct *task;
        // 遍歷所有進程
        for_each_process(task) {
            process_count++;
        }
        written += snprintf(kfetch_buf + written, sizeof(kfetch_buf) - written,
                            "Procs: %d\n", process_count);
    }

    // 複製資料到使用者空間
    if (copy_to_user(buffer, kfetch_buf, written)) {
        printk(KERN_ERR "kfetch: failed to copy data to user space\n");
        mutex_unlock(&kfetch_mutex);
        return -EFAULT;
    }

    // 解鎖
    mutex_unlock(&kfetch_mutex);
    return written; // 返回已傳輸的字節數
}

// write 函數
static ssize_t kfetch_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char user_buf[16];
    unsigned long new_mask;

    // 嘗試取得鎖
    if (!mutex_trylock(&kfetch_mutex)) {
        printk(KERN_WARNING "kfetch: device is busy\n");
        return -EBUSY;
    }

    if (len > sizeof(user_buf) - 1) {
        printk(KERN_ERR "kfetch: input too large\n");
        mutex_unlock(&kfetch_mutex);
        return -EINVAL;
    }

    if (copy_from_user(user_buf, buffer, len)) {
        printk(KERN_ERR "kfetch: failed to copy data from user space\n");
        mutex_unlock(&kfetch_mutex);
        return -EFAULT;
    }

    user_buf[len] = '\0'; // 確保是有效字串
    if (kstrtoul(user_buf, 10, &new_mask)) {
        printk(KERN_ERR "kfetch: invalid input\n");
        mutex_unlock(&kfetch_mutex);
        return -EINVAL;
    }

    info_mask = (int)new_mask; // 更新遮罩
    printk(KERN_INFO "kfetch: updated info_mask to 0x%x\n", info_mask);

    // 解鎖
    mutex_unlock(&kfetch_mutex);
    return len;
}

// 定義 file_operations
static const struct file_operations kfetch_fops = {
    .owner = THIS_MODULE,
    .open = kfetch_open,
    .release = kfetch_release,
    .read = kfetch_read,
    .write = kfetch_write,
};

// 初始化模組
static int __init kfetch_init(void) {
    int ret;

    // 動態分配設備號
    ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "kfetch: failed to allocate device number\n");
        return ret;
    }

    // 初始化字符設備
    cdev_init(&kfetch_cdev, &kfetch_fops);
    ret = cdev_add(&kfetch_cdev, dev_number, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_number, 1);
        printk(KERN_ERR "kfetch: failed to add cdev\n");
        return ret;
    }

    // 創建類別
    kfetch_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(kfetch_class)) {
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev_number, 1);
        printk(KERN_ERR "kfetch: failed to create class\n");
        return PTR_ERR(kfetch_class);
    }

    // 創建設備節點
    if (IS_ERR(device_create(kfetch_class, NULL, dev_number, NULL, DEVICE_NAME))) {
        class_destroy(kfetch_class);
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev_number, 1);
        printk(KERN_ERR "kfetch: failed to create device\n");
        return -1;
    }

    printk(KERN_INFO "kfetch: module loaded\n");
    return 0;
}

// 卸載模組
static void __exit kfetch_exit(void) {
    device_destroy(kfetch_class, dev_number);
    class_destroy(kfetch_class);
    cdev_del(&kfetch_cdev);
    unregister_chrdev_region(dev_number, 1);
    printk(KERN_INFO "kfetch: module unloaded\n");
}

module_init(kfetch_init);
module_exit(kfetch_exit);
