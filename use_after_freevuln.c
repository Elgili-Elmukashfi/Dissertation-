#include <stdlib.h>
#include <stdio.h>

void vulnerable_function() {
    char *buffer = (char*)malloc(10 * sizeof(char));

    // Use the buffer
    sprintf(buffer, "Hello");
    printf("%s\n", buffer);

    // Free the buffer
    free(buffer);

    // Use after free (vulnerability)
    printf("After free: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
