#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

// 全局变量
static int global_counter = 0;
static int global_array[10] = {0};

int main() {
    printf("Before fork: global_counter = %d\n", global_counter);
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // 子进程
        printf("Child: Before modification, global_counter = %d\n", global_counter);
        global_counter = 100;
        global_array[0] = 999;
        printf("Child: After modification, global_counter = %d, global_array[0] = %d\n", 
               global_counter, global_array[0]);
        printf("Child: global_counter address = %p\n", &global_counter);
        return 0;
    } else {
        // 父进程
        wait(NULL); // 等待子进程结束
        printf("Parent: After child finished, global_counter = %d, global_array[0] = %d\n", 
               global_counter, global_array[0]);
        printf("Parent: global_counter address = %p\n", &global_counter);
        
        // 父进程修改
        global_counter = 200;
        printf("Parent: After parent modification, global_counter = %d\n", global_counter);
    }
    
    return 0;
}
