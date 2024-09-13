import re  # Import regular expression module for pattern matching

class SimpleVulnerabilityDetector:
    def __init__(self):
        # Initialize an empty list to store detected vulnerabilities
        self.vulnerabilities = []

    def analyze_file(self, file_path):
        """
        Analyze a single file for vulnerabilities.
        :param file_path: Path to the file to be analyzed
        """
        with open(file_path, 'r') as file:
            content = file.read()
            # Check for different types of vulnerabilities
            self.check_buffer_overflow(content, file_path)
            self.check_format_string(content, file_path)

    def check_buffer_overflow(self, content, file_path):
        """
        Check for potential buffer overflow vulnerabilities.
        :param content: The content of the file being analyzed
        :param file_path: Path to the file (for reporting purposes)
        """
        # List of functions commonly associated with buffer overflows
        unsafe_functions = ['strcpy', 'strcat', 'gets']
        for func in unsafe_functions:
            # Use regex to find function calls
            matches = re.finditer(fr'\b{func}\s*\(', content)
            for match in matches:
                # Calculate the line number of the potential vulnerability
                line_no = content[:match.start()].count('\n') + 1
                # Add the vulnerability to our list
                self.vulnerabilities.append(f"Potential buffer overflow in {file_path}:{line_no} - Usage of {func}")

    def check_format_string(self, content, file_path):
        """
        Check for potential format string vulnerabilities.
        :param content: The content of the file being analyzed
        :param file_path: Path to the file (for reporting purposes)
        """
        # List of functions that can be vulnerable to format string attacks
        format_funcs = ['printf', 'sprintf', 'fprintf']
        for func in format_funcs:
            # Look for function calls with a %s in the first argument
            matches = re.finditer(fr'\b{func}\s*\([^,]*%s', content)
            for match in matches:
                # Calculate the line number of the potential vulnerability
                line_no = content[:match.start()].count('\n') + 1
                # Add the vulnerability to our list
                self.vulnerabilities.append(f"Potential format string vulnerability in {file_path}:{line_no} - Unchecked format string in {func}")

    def report_vulnerabilities(self):
        """
        Report all detected vulnerabilities.
        """
        if not self.vulnerabilities:
            print("No vulnerabilities detected.")
        else:
            print("Vulnerabilities found:")
            for vuln in self.vulnerabilities:
                print(vuln)

# Usage example
if __name__ == "__main__":
    detector = SimpleVulnerabilityDetector()
    # Analyze a specific file - replace with the path to your C/C++ file
    detector.analyze_file("C:\Elgili's Dissertation\Dissertation-/frmt.cpp")
    # Print out the results
    detector.report_vulnerabilities()
