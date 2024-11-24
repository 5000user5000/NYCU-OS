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
#include <linux/version.h>
#include <linux/sched/signal.h> // for signal_struct and for_each_process

#define DEVICE_NAME "kfetch"


// Mask setting
#define KFETCH_NUM_INFO 6
#define KFETCH_RELEASE (1 << 0)  // Kernel release
#define KFETCH_NUM_CPUS (1 << 1) // Number of CPUs
#define KFETCH_CPU_MODEL (1 << 2) // CPU model name
#define KFETCH_MEM (1 << 3) // Memory info
#define KFETCH_UPTIME (1 << 4) // Uptime
#define KFETCH_NUM_PROCS (1 << 5) // Number of processes
#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

#define KFETCH_BUF_SIZE 1024 /* Max length of the message from the device */

// 全域變數
static dev_t dev_number;
static struct cdev kfetch_cdev;
static struct class *kfetch_class;
static char kfetch_buf[KFETCH_BUF_SIZE]; // 用來存儲返回給使用者的資訊
static int kfetch_mask = 0; // 會記住當前 mask 的訊息 <包含之前的，如果沒有帶參數修改的話>

// 定義互斥鎖
DEFINE_MUTEX(kfetch_mutex);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("313551118");
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

char *logo[8] = {
    "                      ",
    "         .-.          ",
    "        (.. |         ",
    "       \033[1;33m <> \033[1;0m |         ",
    "       / --- \\        ",
    "      ( |   | |       ",
    "    \033[1;33m|\\\033[1;0m\\_)___/\\)\033[1;33m/\\ \033[1;0m    ",
    "   \033[1;33m<__)\033[1;0m------\033[1;33m(__/\033[1;0m     ",
};

// read 函數
static ssize_t kfetch_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {

    // ---------   parameters  declarations ---------   

    char* hostname;
    char* kernel_ver;
    char* cpu_model;

    struct cpuinfo_x86 *c = &cpu_data(0);
    struct timespec64 uptime;
    long uptime_mins;
    int online_cpus;
    int total_cpus; 
    struct sysinfo info;
    unsigned long totalram, freeram;
    int process_count = 0;
    char split_line[50];
    // char info_list[8][64];
    // bool contain_info[8] = {true, true, false, false, false, false, false, false};
    // char data_buf[64] = {0}; // 用來暫存資料
    char info_lines[8][64];
    int info_count = 0;
    int sl_idx = 0;
    struct task_struct *task;

    // ---------   code  section ---------   
    // 嘗試取得鎖
    if (!mutex_trylock(&kfetch_mutex)) {
        printk(KERN_WARNING "kfetch: device is busy when reading\n");
        return -EBUSY;
    }

    
    // 遍歷所有進程
    for_each_process(task) {
        process_count++;
    }

    hostname = utsname()->nodename;
    kernel_ver = utsname()->release;

    cpu_model = c->x86_model_id;

    online_cpus = num_online_cpus();
    total_cpus = num_active_cpus(); // num_possible_cpus() ?

    si_meminfo(&info);
    freeram = (info.freeram * info.mem_unit) >> 20;
    totalram = (info.totalram * info.mem_unit) >> 20; // 轉換為 MB

    ktime_get_boottime_ts64(&uptime);
    uptime_mins = uptime.tv_sec / 60;

    // split line
    for(; hostname[sl_idx] != '\0' && sl_idx < 50 ; sl_idx++){
        split_line[sl_idx] = '-';
    }
    split_line[ sl_idx ] = '\0';


    // 清空緩衝區
    memset(kfetch_buf, 0, sizeof(kfetch_buf));

    printk(KERN_INFO "kfetch_mask = %d\n",kfetch_mask);


    // ---------   start to combine info  ---------   
    // Line 0: Hostname
    snprintf(info_lines[info_count++], sizeof(info_lines[0]), "%s", hostname);

    // Line 1: Separator line
    snprintf(info_lines[info_count++], sizeof(info_lines[0]), "%s", split_line);

     // Add information based on the kfetch_mask
    if (kfetch_mask & KFETCH_RELEASE) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mKernel:\033[1;0m %s", kernel_ver);
    }
    if (kfetch_mask & KFETCH_CPU_MODEL) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mCPU:\033[1;0m    %s", cpu_model);
    }
    if (kfetch_mask & KFETCH_NUM_CPUS) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mCPUs:\033[1;0m   %d / %d", online_cpus, total_cpus);
    }
    if (kfetch_mask & KFETCH_MEM) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mMem:\033[1;0m    %lu / %lu MB", freeram, totalram);
    }
    if (kfetch_mask & KFETCH_NUM_PROCS) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mProcs:\033[1;0m  %d", process_count);
    }
    if (kfetch_mask & KFETCH_UPTIME) {
        snprintf(info_lines[info_count++], sizeof(info_lines[0]), "\033[1;33mUptime:\033[1;0m %ld mins", uptime_mins);
    }

    // write to kfetch buf
    strcpy(kfetch_buf, "");
    for (int i = 0 ; i < 8; i++) {
        // Append the logo line
        strlcat(kfetch_buf, logo[i], sizeof(kfetch_buf));

        // Append the corresponding info line if available
        if (i < info_count) {
            strlcat(kfetch_buf, info_lines[i], sizeof(kfetch_buf));
        }

        // Add a newline character
        strlcat(kfetch_buf, "\n", sizeof(kfetch_buf));
    }

    // 複製資料到使用者空間
    if (copy_to_user(buffer, kfetch_buf, sizeof(kfetch_buf))) {
        printk(KERN_ERR "kfetch: failed to copy data to user space\n");
        mutex_unlock(&kfetch_mutex);
        return -EFAULT;
    }

    // 解鎖
    mutex_unlock(&kfetch_mutex);

    return sizeof(kfetch_buf); // 返回已傳輸的字節數
}

// write 函數
static ssize_t kfetch_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    int mask_info;

    // 嘗試取得鎖
    if (!mutex_trylock(&kfetch_mutex)) {
        printk(KERN_WARNING "kfetch: device is busy when writing\n");
        return -EBUSY;
    }

    if (copy_from_user(&mask_info, buffer, len)) {
        printk(KERN_ERR "kfetch: failed to copy data from user space\n");
        mutex_unlock(&kfetch_mutex);
        return -EFAULT;
    }

    kfetch_mask = mask_info; // 更新遮罩
    printk(KERN_INFO "kfetch: updated info_mask to 0x%x\n", kfetch_mask);

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
static int  kfetch_init(void) {
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
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        kfetch_class = class_create(DEVICE_NAME);
    #else
        kfetch_class = class_create(THIS_MODULE, DEVICE_NAME); // I use 6.1.0
    #endif

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

    kfetch_mask = KFETCH_FULL_INFO; // 預設顯示所有訊息

    printk(KERN_INFO "kfetch: module loaded\n");
    return 0;
}

// 卸載模組
static void  kfetch_exit(void) {
    device_destroy(kfetch_class, dev_number);
    class_destroy(kfetch_class);
    cdev_del(&kfetch_cdev);
    unregister_chrdev_region(dev_number, 1);
    printk(KERN_INFO "kfetch: module unloaded\n");
}


module_init(kfetch_init);
module_exit(kfetch_exit);
