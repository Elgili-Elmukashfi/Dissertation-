import re
import sys

class VulnerabilityDetector:
    def __init__(self):
        self.vulnerabilities = []
        self.array_declarations = {}
        self.function_parameters = {}

    def analyze_file(self, filename):
        """
        Analyze a C/C++ file for potential vulnerabilities.
        """
        with open(filename, 'r') as file:
            content = file.read()

        self.find_function_parameters(content)
        self.find_array_declarations(content)

        functions = re.findall(r'(\w+)\s+(\w+)\s*\((.*?)\)\s*{(.*?)}', content, re.DOTALL)
        for func in functions:
            self.analyze_function(func)

    def find_function_parameters(self, content):
        """
        Find all function declarations and store their parameters.
        """
        function_decls = re.findall(r'(\w+)\s+(\w+)\s*\((.*?)\)', content)
        for return_type, func_name, params in function_decls:
            self.function_parameters[func_name] = [p.strip().split()[-1] for p in params.split(',') if p.strip()]

    def find_array_declarations(self, content):
        """
        Find all array declarations in the code and store their sizes.
        """
        array_decls = re.findall(r'(\w+)\s+(\w+)\s*\[(\d+)\]', content)
        for type_, name, size in array_decls:
            self.array_declarations[name] = int(size)

    def analyze_function(self, func):
        """
        Analyze a single function for potential vulnerabilities.
        """
        func_name, params, body = func[1], func[2], func[3]

        for param in self.function_parameters.get(func_name, []):
            if param not in self.array_declarations:
                self.array_declarations[param] = sys.maxsize

        self.check_buffer_overflow(body, func_name)
        self.check_format_string(body, func_name)

    def check_buffer_overflow(self, body, func_name):
        """
        Check for potential buffer overflow vulnerabilities.
        """
        array_accesses = re.findall(r'(\w+)\s*\[([^]]+)\]', body)

        for access in array_accesses:
            self.check_array_access(access, func_name)

    def check_array_access(self, access, func_name):
        """
        Check if an array access might cause a buffer overflow.
        """
        array_name, index_expr = access

        if array_name in self.array_declarations:
            array_size = self.array_declarations[array_name]

            if index_expr.isdigit():
                if int(index_expr) >= array_size:
                    self.vulnerabilities.append(f"Buffer Overflow in '{func_name}': {array_name}[{index_expr}] exceeds declared size of {array_size}")
            else:
                self.analyze_index_expression(array_name, index_expr, array_size, func_name)

    def analyze_index_expression(self, array_name, index_expr, array_size, func_name):
        """
        Analyze a non-constant index expression for potential overflow.
        """
        if '+' in index_expr or '-' in index_expr:
            self.vulnerabilities.append(f"Potential Buffer Overflow in '{func_name}': {array_name}[{index_expr}] - arithmetic operation in index might exceed bounds")
        elif any(var in index_expr for var in self.function_parameters.get(func_name, [])):
            self.vulnerabilities.append(f"Potential Buffer Overflow in '{func_name}': {array_name}[{index_expr}] - using function parameter as index without bounds checking")
        else:
            self.vulnerabilities.append(f"Potential Buffer Overflow in '{func_name}': {array_name}[{index_expr}] - unable to determine bounds at compile time")

    def check_format_string(self, body, func_name):
        """
        Check for potential format string vulnerabilities.
        """
        # Look for printf-like function calls
        printf_calls = re.findall(r'(printf|sprintf|fprintf|snprintf|vprintf|vsprintf|vfprintf|vsnprintf)\s*\((.*?)\)', body)

        for func, args in printf_calls:
            args = [arg.strip() for arg in args.split(',')]
            if len(args) < 2:  # Single argument printf is always safe
                continue

            format_string = args[0 if func == 'printf' else 1]  # printf(format, ...) vs fprintf(stream, format, ...)

            # Check if the format string is a string literal
            if not (format_string.startswith('"') and format_string.endswith('"')):
                # If it's not a string literal, it might be user-controlled
                self.vulnerabilities.append(f"Potential Format String Vulnerability in '{func_name}': {func}() call with non-literal format string")

            # Check for mismatched format specifiers and arguments
            format_specifiers = re.findall(r'%[\d.]*[diuoxXfFeEgGaAcspn]', format_string)
            if len(format_specifiers) != len(args) - (1 if func == 'printf' else 2):
                self.vulnerabilities.append(f"Potential Format String Vulnerability in '{func_name}': Mismatched number of format specifiers and arguments in {func}() call")

    def report_vulnerabilities(self):
        """
        Report all found vulnerabilities.
        """
        if self.vulnerabilities:
            print("Potential vulnerabilities found:")
            for vuln in self.vulnerabilities:
                print(f"- {vuln}")
        else:
            print("No potential vulnerabilities detected.")

# Usage example
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vulnerability_detector.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    detector = VulnerabilityDetector()
    detector.analyze_file(filename)
    detector.report_vulnerabilities()
