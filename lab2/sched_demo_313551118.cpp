#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAX_THREADS 30

typedef struct {
    int thread_id;
    int policy;
    int priority;
    double time_wait;
} thread_data_t;

pthread_barrier_t barrier;

void busy_wait(double seconds) {
    struct timespec start, current;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start); //注意這裡使用的是CLOCK_THREAD_CPUTIME_ID

    while (1) {
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &current);
        double elapsed = (current.tv_sec - start.tv_sec) +
                         (current.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= seconds) break;
    }
}

void *thread_func(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

    // 等待所有執行緒同步啟動
    pthread_barrier_wait(&barrier);

    /* 2. 執行任務 */
    for (int i = 0; i < 3; i++) {
        printf("Thread %d is starting\n", data->thread_id);
        /* 忙碌 <time_wait> 秒 */
        busy_wait(data->time_wait);
    }
    

    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    int num_threads = 0;
    double time_wait = 0;
    char *policy_str = NULL;
    char *priority_str = NULL;
    int policies[MAX_THREADS];
    int priorities[MAX_THREADS];

    // 1. 解析程式參數
    int opt;
    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
            case 'n':
                num_threads = atoi(optarg);
                break;
            case 't':
                time_wait = atof(optarg);
                break;
            case 's':
                policy_str = strdup(optarg);
                break;
            case 'p':
                priority_str = strdup(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -n <num_threads> -t <time_wait> -s <policies> -p <priorities>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (num_threads <= 0 || num_threads > MAX_THREADS) {
        fprintf(stderr, "Invalid number of threads.\n");
        exit(EXIT_FAILURE);
    }

    // 解析排程策略
    char *token = strtok(policy_str, ",");
    for (int i = 0; i < num_threads && token != NULL; i++) {
        if (strcmp(token, "NORMAL") == 0) {
            policies[i] = SCHED_OTHER;
        } else if (strcmp(token, "FIFO") == 0) {
            policies[i] = SCHED_FIFO;
        } else {
            fprintf(stderr, "Invalid scheduling policy: %s\n", token);
            exit(EXIT_FAILURE);
        }
        token = strtok(NULL, ",");
    }

    // 解析優先級
    token = strtok(priority_str, ",");
    for (int i = 0; i < num_threads && token != NULL; i++) {
        priorities[i] = atoi(token);
        token = strtok(NULL, ",");
    }

    // 2. 創建工作執行緒
    pthread_t threads[MAX_THREADS];
    pthread_attr_t attr;
    thread_data_t thread_data[MAX_THREADS];

    pthread_barrier_init(&barrier, NULL, num_threads);

    // 3. 設置 CPU 親和性
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);

    for (int i = 0; i < num_threads; i++) {
        pthread_attr_init(&attr);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);

        // 4. 設置執行緒屬性
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&attr, policies[i]);

        struct sched_param param;
        param.sched_priority = priorities[i];
        pthread_attr_setschedparam(&attr, &param);

        thread_data[i].thread_id = i;
        thread_data[i].policy = policies[i];
        thread_data[i].priority = priorities[i];
        thread_data[i].time_wait = time_wait;

        int rc = pthread_create(&threads[i], &attr, thread_func, (void *)&thread_data[i]);
        if (rc != 0) {
            fprintf(stderr, "Error creating thread %d: %s\n", i, strerror(rc));
            exit(EXIT_FAILURE);
        }
        pthread_attr_destroy(&attr);
    }

    // 5. 等待所有執行緒完成
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&barrier);
    free(policy_str);
    free(priority_str);

    return 0;
}