# PythonProjectScanner 📢
Scanner Tool Like Nmap - Service Banner Grabber

## Overview
A Python-based service banner grabber that connects to open ports and attempts to grab service banners (version information) to check against a local list of known vulnerabilities.

## Features
- 🔍 **Port Scanning**: Scans common service ports (22, 23, 80, 443, 8080, 3306, 5432, 6379)
- 📢 **Banner Grabbing**: Retrieves service banners and version information
- 🛡️ **Vulnerability Detection**: Checks grabbed banners against a database of known vulnerabilities
- 📊 **Detailed Reports**: Generates comprehensive scan reports with vulnerability information

## Key Python Libraries
- `socket`: For network connections and banner grabbing
- `re`: For parsing and extracting version information from banners
- `json`: For vulnerability database management

## Installation
No external dependencies required! Uses only Python standard library.

```bash
# Clone the repository
git clone https://github.com/eyadgamer1/PythonProjectScanner.git
cd PythonProjectScanner

# Make the script executable (optional)
chmod +x banner_grabber.py
```

## Usage

### Basic Usage
Scan a host with default ports:
```bash
python3 banner_grabber.py <target_host>
```

Example:
```bash
python3 banner_grabber.py scanme.nmap.org
```

### Scan Specific Ports
```bash
python3 banner_grabber.py <target_host> -p 22,80,443
```

Example:
```bash
python3 banner_grabber.py example.com -p 80,443,8080
```

### Use Custom Vulnerability Database
```bash
python3 banner_grabber.py <target_host> -d /path/to/custom_vulnerabilities.json
```

### Help
```bash
python3 banner_grabber.py -h
```

## Sample Output
```
Scanning scanme.nmap.org...
============================================================

[+] Port 22 is OPEN
    Service: ssh
    Version: OpenSSH_7.1
    Banner: SSH-2.0-OpenSSH_7.1p2 Ubuntu-4ubuntu2.8...
    ⚠️  VULNERABILITIES FOUND: 1
        - CVE-2016-0777: OpenSSH 7.1p2 client information leak vulnerability

[+] Port 80 is OPEN
    Service: apache
    Version: 2.4.49
    Banner: HTTP/1.1 200 OK Server: Apache/2.4.49...
    ⚠️  VULNERABILITIES FOUND: 1
        - CVE-2021-41773: Path traversal and RCE vulnerability in Apache HTTP Server

============================================================
SCAN SUMMARY
============================================================

Total Ports Scanned: 8
Open Ports: 2
Ports with Vulnerabilities: 2

⚠️  VULNERABLE SERVICES:

  Port 22 - ssh
    - CVE-2016-0777: OpenSSH 7.1p2 client information leak vulnerability

  Port 80 - apache
    - CVE-2021-41773: Path traversal and RCE vulnerability in Apache HTTP Server

============================================================
```

## Vulnerabilities Database
The tool comes with a `vulnerabilities.json` file containing known vulnerabilities for common services:
- SSH (OpenSSH)
- Apache HTTP Server
- Nginx
- MySQL
- FTP
- Telnet
- General HTTP services

You can extend this database by adding more CVE entries following the JSON schema.

## Supported Services
- **SSH** (Port 22)
- **Telnet** (Port 23)
- **HTTP** (Port 80, 8080)
- **HTTPS** (Port 443)
- **MySQL** (Port 3306)
- **PostgreSQL** (Port 5432)
- **Redis** (Port 6379)

## Architecture
The scanner consists of:
1. **BannerGrabber Class**: Main scanner engine
   - `grab_banner()`: Connects to ports and retrieves banners
   - `extract_version()`: Parses version information using regex
   - `check_vulnerabilities()`: Matches versions against vulnerability database
   - `scan_port()`: Scans individual ports
   - `scan_host()`: Scans multiple ports on a host

2. **Vulnerabilities Database**: JSON file with CVE information
   - CVE identifiers
   - Vulnerable versions
   - Keywords for pattern matching
   - Severity levels
   - Descriptions

## Ethical Use Notice
⚠️ **Important**: This tool is for educational purposes and authorized security testing only. Always ensure you have explicit permission before scanning any target. Unauthorized port scanning may be illegal in your jurisdiction.

## Contributing
Contributions are welcome! Feel free to:
- Add more vulnerabilities to the database
- Improve banner parsing patterns
- Add support for more services
- Enhance reporting features

## License
Open source - feel free to use and modify for educational and authorized security testing purposes. 
