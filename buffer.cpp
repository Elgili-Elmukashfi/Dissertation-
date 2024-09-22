#include <stdio.h>
#include <string.h>

void buffer_overflow_function(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Potential buffer overflow
}

void format_string_function(char* input) {
    printf(input);  // Potential format string vulnerability
}

void array_out_of_bounds(int index) {
    int array[5] = {1, 2, 3, 4, 5};
    printf("%d\n", array[index]);  // Potential out of bounds access
}

int main() {
    char input[100];
    int index;

    printf("Enter a string: ");
    scanf("%s", input);
    buffer_overflow_function(input);

    printf("Enter a format string: ");
    scanf("%s", input);
    format_string_function(input);

    printf("Enter an array index: ");
    scanf("%d", &index);
    array_out_of_bounds(index);

    return 0;
}
