import re
import sys
import ast
from typing import List, Dict, Tuple

class VulnerabilityDetector:
    def __init__(self):
        # Initialize data structures to store vulnerability information
        self.vulnerabilities: List[Dict[str, str]] = []
        self.array_declarations: Dict[str, int] = {}
        self.function_parameters: Dict[str, List[str]] = {}
        self.variable_declarations: Dict[str, str] = {}
        self.variable_initializations: Dict[str, bool] = {}
        self.current_function: str = ""
        self.current_line: int = 0
        self.allocated_memory: Dict[str, str] = {}  # Track allocated memory

    def analyze_file(self, filename: str) -> None:
        """
        Analyze a C/C++ file for potential vulnerabilities.
        """
        # Read the entire file content
        with open(filename, 'r') as file:
            content = file.read()

        # Perform initial analysis to gather information about the code structure
        self.find_function_parameters(content)
        self.find_array_declarations(content)
        self.find_variable_declarations(content)

        # Find all function definitions and analyze each function
        functions = re.findall(r'(\w+)\s+(\w+)\s*\((.*?)\)\s*{(.*?)}', content, re.DOTALL)
        for func in functions:
            self.analyze_function(func)

    def find_function_parameters(self, content: str) -> None:
        """
        Find all function declarations and store their parameters.
        """
        function_decls = re.findall(r'(\w+)\s+(\w+)\s*\((.*?)\)', content)
        for return_type, func_name, params in function_decls:
            self.function_parameters[func_name] = [p.strip().split()[-1] for p in params.split(',') if p.strip()]

    def find_array_declarations(self, content: str) -> None:
        """
        Find all array declarations in the code and store their sizes.
        """
        array_decls = re.findall(r'(\w+)\s+(\w+)\s*\[(\d+)\]', content)
        for type_, name, size in array_decls:
            self.array_declarations[name] = int(size)

    def find_variable_declarations(self, content: str) -> None:
        """
        Find all variable declarations in the code.
        """
        var_decls = re.findall(r'\b(int|long|short|char|float|double)\s+(\w+)\s*;', content)
        for type_, name in var_decls:
            self.variable_declarations[name] = type_

    def analyze_function(self, func: Tuple[str, str, str, str]) -> None:
        """
        Analyze a single function for potential vulnerabilities.
        """
        self.current_function = func[1]
        body = func[3]
        # Reset variable initializations for each function
        self.variable_initializations = {var: False for var in self.variable_declarations}
        self.allocated_memory.clear()  # Reset allocated memory for each function

        # Analyze each line of the function
        lines = body.split('\n')
        for i, line in enumerate(lines):
            self.current_line = i + 1
            self.check_buffer_overflow(line)
            self.check_format_string(line)
            self.check_uninitialized_integer_overflow(line)
            self.check_use_after_free(line)
            self.check_weak_credentials(line)

        print(f"Analyzed function: {self.current_function}")
        print(f"Allocated memory at end of function: {self.allocated_memory}")

    def add_vulnerability(self, vuln_type: str, description: str) -> None:
        """
        Add a vulnerability to the list with additional context.
        """
        self.vulnerabilities.append({
            "type": vuln_type,
            "function": self.current_function,
            "line": self.current_line,
            "description": description
        })

    def check_buffer_overflow(self, line: str) -> None:
        """
        Check for potential buffer overflow vulnerabilities.
        """
        # Find all array accesses in the line
        array_accesses = re.findall(r'(\w+)\s*\[([^]]+)\]', line)

        for access in array_accesses:
            self.check_array_access(access)

    def check_array_access(self, access: Tuple[str, str]) -> None:
        """
        Check if an array access might cause a buffer overflow.
        """
        array_name, index_expr = access

        if array_name in self.array_declarations:
            array_size = self.array_declarations[array_name]

            try:
                # Try to evaluate the index expression
                index_value = ast.literal_eval(index_expr)
                if isinstance(index_value, int) and index_value >= array_size:
                    self.add_vulnerability("Buffer Overflow", f"{array_name}[{index_expr}] exceeds declared size of {array_size}")
            except:
                # If evaluation fails, check for potential issues
                if '+' in index_expr or '-' in index_expr:
                    self.add_vulnerability("Potential Buffer Overflow", f"{array_name}[{index_expr}] - arithmetic operation in index might exceed bounds")
                elif any(var in index_expr for var in self.function_parameters.get(self.current_function, [])):
                    self.add_vulnerability("Potential Buffer Overflow", f"{array_name}[{index_expr}] - using function parameter as index without bounds checking")

    def check_format_string(self, line: str) -> None:
        """
        Check for potential format string vulnerabilities.
        """
        # Find all printf-like function calls
        printf_calls = re.findall(r'(printf|sprintf|fprintf|snprintf|vprintf|vsprintf|vfprintf|vsnprintf)\s*\((.*?)\)', line)

        for func, args in printf_calls:
            args = [arg.strip() for arg in args.split(',')]
            if len(args) < 2:
                continue

            format_string = args[0 if func == 'printf' else 1]

            # Check if format string is a literal string
            if not (format_string.startswith('"') and format_string.endswith('"')):
                self.add_vulnerability("Format String", f"{func}() call with non-literal format string")

            # Check if number of format specifiers matches number of arguments
            format_specifiers = re.findall(r'%[\d.]*[diuoxXfFeEgGaAcspn]', format_string)
            if len(format_specifiers) != len(args) - (1 if func == 'printf' else 2):
                self.add_vulnerability("Format String", f"Mismatched number of format specifiers and arguments in {func}() call")

    def check_uninitialized_integer_overflow(self, line: str) -> None:
        """
        Check for potential uninitialized variable and integer overflow vulnerabilities.
        """
        # Check for variable initializations
        initializations = re.findall(r'(\w+)\s*=', line)
        for var in initializations:
            if var in self.variable_declarations:
                self.variable_initializations[var] = True

        # Check for arithmetic operations
        arithmetic_ops = re.findall(r'(\w+)\s*([\+\-\*\/])\s*(\w+)', line)
        for var1, op, var2 in arithmetic_ops:
            # Check for uninitialized variables
            if var1 in self.variable_declarations and not self.variable_initializations.get(var1, False):
                self.add_vulnerability("Uninitialized Variable", f"Use of potentially uninitialized variable '{var1}' in arithmetic operation")
            if var2 in self.variable_declarations and not self.variable_initializations.get(var2, False):
                self.add_vulnerability("Uninitialized Variable", f"Use of potentially uninitialized variable '{var2}' in arithmetic operation")

            # Check for potential integer overflows
            if op in ['+', '*']:  # Focus on addition and multiplication
                if (var1 in self.variable_declarations and self.variable_declarations[var1] in ['int', 'long']) or \
                   (var2 in self.variable_declarations and self.variable_declarations[var2] in ['int', 'long']):
                    self.add_vulnerability("Potential Integer Overflow", f"Arithmetic operation '{op}' involving '{var1}' and '{var2}' may cause overflow")

    def check_use_after_free(self, line: str) -> None:
        """
        Check for potential Use-After-Free vulnerabilities.
        """
        print(f"Analyzing line {self.current_line}: {line.strip()}")

        # Check for memory allocation
        malloc_match = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\(', line)
        if malloc_match:
            var_name = malloc_match.group(1)
            self.allocated_memory[var_name] = "allocated"
            print(f"Detected allocation of {var_name}")

        # Check for memory deallocation
        free_match = re.search(r'free\((\w+)\)', line)
        if free_match:
            var_name = free_match.group(1)
            if var_name in self.allocated_memory:
                self.allocated_memory[var_name] = "freed"
                print(f"Detected freeing of {var_name}")

        # Check for use of potentially freed memory
        for var_name, status in self.allocated_memory.items():
            if status == "freed" and re.search(r'\b' + re.escape(var_name) + r'\b', line):
                if not re.search(r'free\(' + re.escape(var_name) + r'\)', line):  # Exclude the free statement itself
                    self.add_vulnerability("Use-After-Free", f"Potential use of freed memory '{var_name}'")
                    print(f"Detected potential use after free of {var_name}")

    def check_weak_credentials(self, line: str) -> None:
        """
        Check for potential weak or hard-coded credentials vulnerabilities.
        """
        # Check for hard-coded passwords
        password_patterns = [
            r'password\s*=\s*["\'](.*?)["\']',
            r'passwd\s*=\s*["\'](.*?)["\']',
            r'pwd\s*=\s*["\'](.*?)["\']',
            r'pass\s*=\s*["\'](.*?)["\']'
        ]

        for pattern in password_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                password = match.group(1)
                if len(password) < 8:
                    self.add_vulnerability("Weak Password", f"Potentially weak password: '{password}'")
                self.add_vulnerability("Hard-coded Credential", f"Hard-coded password detected: '{password}'")

        # Check for hard-coded API keys or tokens
        api_key_patterns = [
            r'api[_-]?key\s*=\s*["\'](.*?)["\']',
            r'api[_-]?token\s*=\s*["\'](.*?)["\']',
            r'secret[_-]?key\s*=\s*["\'](.*?)["\']'
        ]

        for pattern in api_key_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                api_key = match.group(1)
                self.add_vulnerability("Hard-coded Credential", f"Hard-coded API key or token detected: '{api_key}'")

        # Check for common default passwords
        default_passwords = ['admin', 'password', '123456', 'qwerty', 'letmein']
        for default_pwd in default_passwords:
            if default_pwd in line.lower():
                self.add_vulnerability("Weak Password", f"Potentially weak default password detected: '{default_pwd}'")

    def report_vulnerabilities(self) -> None:
        """
        Report all found vulnerabilities.
        """
        if self.vulnerabilities:
            print("Potential vulnerabilities found:")
            for vuln in self.vulnerabilities:
                print(f"- {vuln['type']} in function '{vuln['function']}' at line {vuln['line']}: {vuln['description']}")
        else:
            print("No potential vulnerabilities detected.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python vulns_detector.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    detector = VulnerabilityDetector()
    detector.analyze_file(filename)
    detector.report_vulnerabilities()

if __name__ == "__main__":
    main()
