# XSS_Scan

## Overview

**XSS_Scan** is a professional tool for penetration testers and security enthusiasts, designed to automate the discovery of Cross-Site Scripting (XSS) vulnerabilities in web applications. It combines traditional reflected XSS scanning with optional browser-based detection using Selenium, making it suitable for both client-side and server-side vulnerability assessments.

> **Ethical Notice:**  
> Use this tool only on systems you own or have explicit permission to test. Unauthorized use is strictly prohibited.

## Features

- Automated scanning for reflected, stored, and DOM-based XSS
- Supports GET and POST requests with custom payloads
- Discovers and tests forms on target web pages
- Can utilize Selenium for advanced browser-based XSS detection
- Customizable User-Agent, proxy support, and random delays for stealth
- Saves findings and results to `results.txt`
- Verbose output for detailed analysis

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mokhtar2040/XSS_Scan.git
   cd XSS_Scan
   ```
2. **Install dependencies:**
   ```bash
   pip install requests
   ```
   For browser-based testing (optional):
   ```bash
   pip install selenium
   # Download ChromeDriver and ensure it's available in your PATH
   ```

## Usage

```bash
python XssScan.py -u <target_url> -p <payloads_file> [options]
```

### Options

| Option           | Description                                  |
|------------------|----------------------------------------------|
| `-u`, `--url`    | Target URL to scan                           |
| `-p`, `--payloads`| File containing one payload per line         |
| `-v`, `--verbose`| Enable verbose output                        |
| `-s`, `--selenium`| Use Selenium for browser-based checking      |
| `--proxy`        | Specify HTTP proxy (e.g., http://127.0.0.1:8080) |

### Example

```bash
python XssScan.py -u https://example.com -p payloads.txt -v --proxy http://127.0.0.1:8080
python XssScan.py -u https://example.com/login -p payloads.txt -s


## Reporting

- All XSS findings are saved to `results.txt` in the current directory.
- Review this file after each scan for a summary of detected vulnerabilities.

## Contributing

Contributions, suggestions, and bug reports are welcome!  
Please open an issue or submit a pull request.

## License

Open-source for educational and authorized security testing purposes.

**Author:** Eng Mokhtar Alhamadi  
**Twitter (X):** [@M_Alhamadee](https://twitter.com/M_Alhamadee)
