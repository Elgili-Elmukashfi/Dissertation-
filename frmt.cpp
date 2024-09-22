#include <stdio.h>
#include <stdlib.h>

void direct_user_input(char *user_input) {
    printf(user_input);  // Vulnerability: Direct use of user input as format string
}

void indirect_format_string(char *format) {
    char buffer[100];
    sprintf(buffer, format);  // Vulnerability: Indirect use of format string
    printf("%s", buffer);
}

void mismatched_arguments() {
    printf("%d %s", 42);  // Vulnerability: Mismatched format specifiers and arguments
}

void correct_usage(char *user_input) {
    printf("%s", user_input);  // Correct: User input is not used as format string
}

int main() {
    char user_input[100];

    printf("Enter a string: ");
    fgets(user_input, sizeof(user_input), stdin);

    direct_user_input(user_input);
    indirect_format_string(user_input);
    mismatched_arguments();
    correct_usage(user_input);

    return 0;
}
