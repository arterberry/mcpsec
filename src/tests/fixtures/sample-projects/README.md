# Sample Projects for Unit Tests

This directory contains sample projects used for unit testing the `mcpsec` tool. Each subdirectory represents a different project configuration designed to test specific features or scenarios.

## Project Structure

Each sample project typically includes:

- **`mcpsec.yml`**: The configuration file for `mcpsec`.
- **Source code files**: Example code in various languages (e.g., Python, JavaScript) with potential security vulnerabilities or patterns that `mcpsec` should detect.
- **Other relevant files**: Depending on the test case, this might include dependency files (e.g., `requirements.txt`, `package.json`), build scripts, etc.

## Adding New Sample Projects

To add a new sample project for testing:

1. Create a new subdirectory within this directory.
2. Populate the subdirectory with the necessary files for your test case (e.g., `mcpsec.yml`, source files).
3. Ensure the project configuration and code demonstrate the specific scenario you want to test.
4. Update the relevant unit tests in the `tests` directory to utilize the new sample project.

These sample projects are crucial for ensuring the reliability and correctness of `mcpsec` across various project types and configurations.
