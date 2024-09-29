#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_REQUEST_SIZE 1024
#define MAX_RESPONSE_SIZE 2048
#define SERVER_PORT 8080

// Vulnerable: Hard-coded credentials
const char* ADMIN_PASSWORD = "admin123";

void log_message(const char* format, const char* message) {
    char buffer[100];
    // Vulnerable: Format string vulnerability
    sprintf(buffer, format, message);
    printf("%s\n", buffer);
}

void handle_request(int client_socket) {
    char request[MAX_REQUEST_SIZE];
    char response[MAX_RESPONSE_SIZE];
    int bytes_received;

    // Vulnerable: Potential buffer overflow
    bytes_received = recv(client_socket, request, sizeof(request), 0);
    request[bytes_received] = '\0';

    // Vulnerable: Uninitialized variable
    char* method;
    char* path;

    // Parse request (simplified)
    method = strtok(request, " ");
    path = strtok(NULL, " ");

    // Vulnerable: Potential buffer overflow
    snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nRequested Path: %s",
             strlen(path) + 16, path);

    send(client_socket, response, strlen(response), 0);

    log_message("Handled request for path: %s", path);

    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", SERVER_PORT);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        handle_request(client_socket);
    }

    close(server_socket);
    return 0;
}
