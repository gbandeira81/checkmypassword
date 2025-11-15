# Password Checker

A Python script that checks if your passwords have been compromised in data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/) API.

## What It Does

This tool allows you to check whether your passwords have been found in known data breaches. It uses the Have I Been Pwned API with k-anonymity, which means your full password is never sent over the network - only the first 5 characters of its SHA-1 hash are transmitted, ensuring your privacy.

## How It Works

1. Takes one or more passwords as command-line arguments
2. Converts each password to a SHA-1 hash
3. Sends only the first 5 characters of the hash to the Have I Been Pwned API
4. Receives a list of matching hash suffixes and their breach counts
5. Checks if your password's hash suffix appears in the results
6. Reports how many times the password was found in breaches

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone or download this repository

2. Install the required dependency:
```bash
pip install requests
```

## Usage

Run the script from the command line, passing one or more passwords as arguments:

```bash
python checkmypass.py password1 password2 password3
```

### Example

```bash
python checkmypass.py mypassword123
```

**Output:**
- If the password was found: `mypassword123 was found 12345 times. You should change your password!`
- If the password was not found: `mypassword123 was not found. Carry On!`

## Testing

This project includes comprehensive unit tests. The test suite uses mocking to avoid making actual API calls, ensuring fast and reliable tests.

### Running Tests

You can run the tests using either `pytest` or Python's built-in `unittest`:

**Using pytest:**
```bash
python -m pytest test_checkmypass.py -v
```

**Using unittest:**
```bash
python -m unittest test_checkmypass.py -v
```

### Test Coverage

The test suite includes 14 test cases covering:
- API request success and error handling
- Password leak count detection (found, not found, empty responses)
- SHA-1 hash generation and password checking
- Main function output and behavior

All tests use mocking to prevent actual network requests during testing.

## License

This project is provided as-is for educational purposes.

