#include <stdio.h>
#include <limits.h>

void uninitialized_variable() {
    int x;
    int y = 10;
    int z = x + y;  // x is uninitialized
    printf("%d\n", z);
}

void potential_overflow(int a, int b) {
    int result = a + b;  // Potential overflow
    printf("%d\n", result);
}

void safe_operation() {
    int a = 5;
    int b = 10;
    int result = a + b;  // This should be safe
    printf("%d\n", result);
}

int main() {
    uninitialized_variable();
    potential_overflow(INT_MAX, 1);  // Potential overflow with INT_MAX + 1
    safe_operation();
    return 0;
}
