#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[20];

    gets(input);  // Unsafe function
    strcpy(buffer, input);  // Potential buffer overflow

    printf(input);  // Potential format string vulnerability

    return 0;
}
