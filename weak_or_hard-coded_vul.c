#include <stdio.h>
#include <string.h>

void login_function() {
    char password[20] = "123456";  // Weak password
    char api_key[50] = "AIzaSyDI3pGGhZaXvtBa28TIkoFTXkqVYWDtRdQ";  // Hard-coded API key

    printf("Enter password: ");
    char input[20];
    scanf("%s", input);

    if (strcmp(input, password) == 0) {
        printf("Login successful!\n");
    } else {
        printf("Login failed.\n");
    }
}

void config_function() {
    char admin_pwd[] = "admin";  // Common default password
    char secret_token[] = "my_secret_token_1234";  // Hard-coded token

    printf("Admin password: %s\n", admin_pwd);
    printf("Secret token: %s\n", secret_token);
}

int main() {
    login_function();
    config_function();
    return 0;
}
