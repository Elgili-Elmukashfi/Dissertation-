#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUFFER_SIZE 1024
#define MAX_STRING_LENGTH 256
#define MAX_ARRAY_SIZE 1000

// Error codes
#define SUCCESS 0
#define ERROR_NULL_POINTER -1
#define ERROR_INVALID_INPUT -2
#define ERROR_MEMORY_ALLOCATION -3
#define ERROR_BUFFER_OVERFLOW -4

// Struct for linked list
typedef struct Node {
    int data;
    struct Node* next;
} Node;

// Global pointer for demonstrating use-after-free
Node* global_node = NULL;

// Vulnerable: Potential integer overflow
void* safe_malloc(size_t size) {
    // Vulnerable: No check for size being 0 or very large
    void* ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Vulnerable: Potential use-after-free
char* string_duplicate(const char* str) {
    if (str == NULL) {
        return NULL;
    }
    char* dup = (char*)safe_malloc(strlen(str) + 1);
    strcpy(dup, str);
    return dup;
}

// Vulnerable: Potential buffer overflow
void string_concat(char* dest, const char* src) {
    // Vulnerable: No bounds checking
    strcat(dest, src);
}

// Vulnerable: Potential buffer overflow
void string_copy(char* dest, const char* src) {
    // Vulnerable: No bounds checking
    strcpy(dest, src);
}

// Vulnerable: Uninitialized variable
int process_data(const char* data) {
    int result;
    if (strlen(data) > 0) {
        result = atoi(data);
    }
    // Vulnerable: result may be used uninitialized if data is empty
    return result * 2;
}

// Vulnerable: Integer overflow
size_t calculate_buffer_size(int width, int height) {
    // Vulnerable: No check for overflow
    return width * height * sizeof(int);
}

// Vulnerable: Off-by-one error
void initialize_buffer(int* buffer, int size) {
    // Vulnerable: <= should be <
    for (int i = 0; i <= size; i++) {
        buffer[i] = 0;
    }
}

// Vulnerable: Null pointer dereference
int get_string_length(const char* str) {
    // Vulnerable: No null check
    return strlen(str);
}

// Vulnerable: Division by zero
float calculate_average(int* numbers, int count) {
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += numbers[i];
    }
    // Vulnerable: No check for count being zero
    return (float)sum / count;
}

// Vulnerable: Memory leak
char* create_padded_string(const char* input, int padding) {
    int length = strlen(input);
    char* padded = (char*)safe_malloc(length + padding + 1);
    strcpy(padded, input);
    for (int i = length; i < length + padding; i++) {
        padded[i] = ' ';
    }
    padded[length + padding] = '\0';
    // Vulnerable: Function doesn't free 'padded' if it's not used
    return padded;
}

// New function: Vulnerable to integer overflow
int64_t multiply_and_add(int32_t a, int32_t b, int32_t c) {
    // Vulnerable: No overflow check
    return (int64_t)a * b + c;
}

// New function: Vulnerable to buffer overflow
int copy_and_capitalize(char* dest, const char* src, size_t dest_size) {
    size_t src_len = strlen(src);
    // Vulnerable: Incorrect bounds checking
    if (src_len > dest_size) {
        return ERROR_BUFFER_OVERFLOW;
    }

    for (size_t i = 0; i < src_len; i++) {
        dest[i] = (src[i] >= 'a' && src[i] <= 'z') ? src[i] - 32 : src[i];
    }
    dest[src_len] = '\0';

    return SUCCESS;
}

// New function: Vulnerable to null pointer dereference and buffer overflow
int string_to_integer_array(const char* str, int* arr, int max_size) {
    // Vulnerable: No null check for str or arr
    int count = 0;
    char* token = strtok((char*)str, ",");

    while (token != NULL && count < max_size) {
        arr[count++] = atoi(token);
        token = strtok(NULL, ",");
    }

    return count;
}

// New function: Vulnerable to integer overflow
uint32_t calculate_factorial(uint32_t n) {
    // Vulnerable: No overflow check
    if (n == 0 || n == 1) {
        return 1;
    }
    return n * calculate_factorial(n - 1);
}

// New function: Vulnerable to buffer overflow and format string vulnerability
void log_message(const char* format, const char* message) {
    char buffer[100];
    // Vulnerable: No bounds checking and format string vulnerability
    sprintf(buffer, format, message);
    printf("%s\n", buffer);
}

// New function: Vulnerable to use-after-free
char* resize_and_copy(char* original, size_t new_size) {
    char* new_str = (char*)realloc(original, new_size);
    if (new_str == NULL) {
        // Vulnerable: original is freed but might be used later
        free(original);
        return NULL;
    }
    return new_str;
}

// New function: Vulnerable to integer overflow and buffer overflow
int sum_array_elements(int* arr, size_t size) {
    int sum = 0;
    // Vulnerable: No overflow check for sum
    for (size_t i = 0; i <= size; i++) {  // Vulnerable: Off-by-one error
        sum += arr[i];
    }
    return sum;
}

// New function: Vulnerable to null pointer dereference and memory leak
char* concatenate_strings(const char* str1, const char* str2) {
    // Vulnerable: No null checks
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char* result = (char*)safe_malloc(len1 + len2 + 1);
    strcpy(result, str1);
    strcat(result, str2);
    // Vulnerable: Memory leak if result is not freed by caller
    return result;
}

// New function: Vulnerable to use-after-free (first additional use-after-free)
void process_and_free_node(Node* node) {
    printf("Processing node with data: %d\n", node->data);
    free(node);
    // Vulnerable: node is used after being freed
    global_node = node;
}

// New function: Vulnerable to use-after-free (second additional use-after-free)
char* get_and_process_string() {
    char* str = (char*)safe_malloc(100);
    strcpy(str, "Hello, World!");
    printf("String: %s\n", str);
    free(str);
    // Vulnerable: str is used after being freed
    return str;
}

// New function: Vulnerable to uninitialized variable (additional uninitialized variable)
int complex_calculation(int a, int b) {
    int result;
    int temp;
    if (a > b) {
        temp = a - b;
    } else if (a < b) {
        temp = b - a;
    }
    // Vulnerable: temp may be uninitialized if a == b
    result = temp * 2;
    return result;
}

// Test function to demonstrate usage and vulnerabilities
void test_utils() {
    // Previous test cases...

    // Test process_and_free_node (use-after-free)
    Node* test_node = (Node*)safe_malloc(sizeof(Node));
    test_node->data = 42;
    test_node->next = NULL;
    process_and_free_node(test_node);
    // Vulnerable: Using freed memory
    printf("Global node data: %d\n", global_node->data);

    // Test get_and_process_string (use-after-free)
    char* processed_str = get_and_process_string();
    // Vulnerable: Using freed memory
    printf("Processed string: %s\n", processed_str);

    // Test complex_calculation (uninitialized variable)
    int calc_result = complex_calculation(5, 5);
    printf("Complex calculation result: %d\n", calc_result);

    // Other test cases...
}

int main() {
    test_utils();
    return 0;
}
