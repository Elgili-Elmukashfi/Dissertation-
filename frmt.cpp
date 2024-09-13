#include <iostream>
#include <cstdio>

void vulnerableFunction(char *input) {
    // Format string vulnerability: no format specifier used
    printf(input);
}

int main() {
    char userInput[100];
    std::cout << "Enter some text: ";
    std::cin >> userInput;
    vulnerableFunction(userInput);
    return 0;
}
