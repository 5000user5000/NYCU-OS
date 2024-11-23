#ifndef KFETCH_H
#define KFETCH_H

// 掩碼設置
#define KFETCH_NUM_INFO 6
#define KFETCH_RELEASE (1 << 0)  // Kernel release
#define KFETCH_NUM_CPUS (1 << 1) // Number of CPUs
#define KFETCH_CPU_MODEL (1 << 2) // CPU model name
#define KFETCH_MEM (1 << 3) // Memory info
#define KFETCH_UPTIME (1 << 4) // Uptime
#define KFETCH_NUM_PROCS (1 << 5) // Number of processes
#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

#endif // KFETCH_H