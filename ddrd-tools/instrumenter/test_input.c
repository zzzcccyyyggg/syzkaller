// 测试用的简单C代码
#include <stdio.h>

int global_var = 0;

int test_function(int a, int b) {
    global_var = a + b;
    return global_var;
}

int main() {
    int result = test_function(10, 20);
    printf("Result: %d\n", result);
    return 0;
}
