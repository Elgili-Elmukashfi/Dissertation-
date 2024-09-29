#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_DEVICES 10
#define MAX_NAME_LENGTH 50
#define MAX_LOG_SIZE 1000
#define TEMP_BUFFER_SIZE 100

// Struct definitions
typedef struct {
    char name[MAX_NAME_LENGTH];
    int status;
    float temperature;
} Device;

typedef struct LogEntry {
    char message[MAX_LOG_SIZE];
    struct LogEntry* next;
} LogEntry;

// Global variables
Device devices[MAX_DEVICES];
int device_count = 0;
LogEntry* log_head = NULL;
char* admin_password = "admin123"; // Vulnerable: Hard-coded credential

// Function prototypes
void initialize_system();
int add_device(const char* name);
void update_device_status(int index, int status);
void update_device_temperature(int index, float temperature);
void log_event(const char* message);
void print_device_info(int index);
float calculate_average_temperature();
void process_user_command(const char* command);
void free_logs();

// Removed buffer overflow vulnerability
void initialize_system() {
    log_event("System initialized");
}

// Removed buffer overflow, kept array index out of bounds vulnerability
int add_device(const char* name) {
    if (device_count < MAX_DEVICES) {
        strncpy(devices[device_count].name, name, MAX_NAME_LENGTH - 1);
        devices[device_count].name[MAX_NAME_LENGTH - 1] = '\0';
        devices[device_count].status = 0;
        devices[device_count].temperature = 0.0f;
        return device_count++;
    }
    return -1;
}

// Vulnerable: No bounds checking
void update_device_status(int index, int status) {
    devices[index].status = status;
    char log_message[100];
    snprintf(log_message, sizeof(log_message), "Device %d status updated to %d", index, status);
    log_event(log_message);
}

// Vulnerable: No input validation
void update_device_temperature(int index, float temperature) {
    devices[index].temperature = temperature;
    char log_message[100];
    snprintf(log_message, sizeof(log_message), "Device %d temperature updated to %.2f", index, temperature);
    log_event(log_message);
}

// Vulnerable: Memory leak
void log_event(const char* message) {
    LogEntry* new_entry = (LogEntry*)malloc(sizeof(LogEntry));
    strncpy(new_entry->message, message, MAX_LOG_SIZE - 1);
    new_entry->message[MAX_LOG_SIZE - 1] = '\0';
    new_entry->next = log_head;
    log_head = new_entry;
}

// Vulnerable: Format string
void print_device_info(int index) {
    printf(devices[index].name);
    printf("\nStatus: %d\n", devices[index].status);
    printf("Temperature: %.2f\n", devices[index].temperature);
}

// Vulnerable: Integer overflow and division by zero
float calculate_average_temperature() {
    int64_t sum = 0;
    for (int i = 0; i < device_count; i++) {
        sum += (int64_t)(devices[i].temperature * 100);
    }
    return (float)sum / (device_count * 100); // Vulnerable: No check for device_count being zero
}

// Vulnerable: Enhanced use-after-free
LogEntry* get_last_log() {
    if (log_head == NULL) {
        return NULL;
    }
    LogEntry* last = log_head;
    while (last->next != NULL) {
        last = last->next;
    }
    return last;
}

void clear_logs() {
    LogEntry* current = log_head;
    while (current != NULL) {
        LogEntry* next = current->next;
        free(current);
        current = next;
    }
    log_head = NULL;
}

void print_last_log() {
    LogEntry* last = get_last_log();
    if (last != NULL) {
        printf("Last log: %s\n", last->message);
    }
}

// Vulnerable: Command injection
void execute_system_command(const char* command) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "sh -c '%s'", command);
    system(buffer);
}

// Vulnerable: SQL injection
void query_device_data(const char* device_name) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT * FROM devices WHERE name = '%s'", device_name);
    // Simulate database query execution
    printf("Executing query: %s\n", query);
}

// Vulnerable: Uninitialized variable
int compute_checksum(const char* data, int length) {
    int checksum;
    for (int i = 0; i < length; i++) {
        checksum += data[i]; // Vulnerable: checksum is uninitialized
    }
    return checksum;
}

// Vulnerable: Off-by-one error
void copy_device_names(char** dest, int max_devices) {
    for (int i = 0; i <= max_devices; i++) { // Vulnerable: Should be < instead of <=
        dest[i] = strdup(devices[i].name);
    }
}

// Vulnerable: Use of dangerous function
void process_user_input(char* buffer, size_t buffer_size) {
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        // Handle error
        return;
    }
    // Remove newline if present
    buffer[strcspn(buffer, "\n")] = 0;
}

// Vulnerable: Null pointer dereference
void update_device_name(int index, const char* new_name) {
    if (index >= 0 && index < device_count) {
        strncpy(devices[index].name, new_name, MAX_NAME_LENGTH - 1);
        devices[index].name[MAX_NAME_LENGTH - 1] = '\0';
    } else {
        devices[index].name[0] = '\0'; // Vulnerable: May dereference null if index is out of bounds
    }
}

// Vulnerable: Race condition
int shared_value = 0;
void increment_shared_value() {
    int temp = shared_value;
    // Simulating some delay
    for (int i = 0; i < 1000000; i++) {}
    shared_value = temp + 1; // Vulnerable: Race condition
}

// Vulnerable: Integer underflow
unsigned int calculate_time_difference(unsigned int start, unsigned int end) {
    return end - start; // Vulnerable: Can underflow if end < start
}

// Main function to tie everything together
int main() {
    initialize_system();

    add_device("Living Room Light");
    add_device("Kitchen Thermostat");
    add_device("Front Door Lock");

    update_device_status(0, 1);
    update_device_temperature(1, 22.5f);

    print_device_info(0);
    print_device_info(1);

    float avg_temp = calculate_average_temperature();
    printf("Average temperature: %.2f\n", avg_temp);

    log_event("System check completed");
    print_last_log();

    // Use-after-free vulnerability demonstration
    clear_logs();
    print_last_log(); // Accessing freed memory

    execute_system_command("echo Hello, World!");
    query_device_data("Living Room Light");

    char data[] = "test data";
    int checksum = compute_checksum(data, strlen(data));
    printf("Checksum: %d\n", checksum);

    char* device_name_copies[MAX_DEVICES];
    copy_device_names(device_name_copies, MAX_DEVICES);

    char user_input[100];
    process_user_input(user_input, sizeof(user_input));
    printf("Processed input: %s\n", user_input);

    update_device_name(5, "New Device"); // Intentionally using out-of-bounds index

    for (int i = 0; i < 5; i++) {
        increment_shared_value();
    }

    unsigned int time_diff = calculate_time_difference(100, 50);
    printf("Time difference: %u\n", time_diff);

    return 0;
}
