# Service Banner Grabber - Quick Usage Guide

## Quick Start

### 1. Basic Scan
Scan a host with default ports (22, 23, 80, 443, 8080, 3306, 5432, 6379):
```bash
python3 banner_grabber.py <target_host>
```

Example:
```bash
python3 banner_grabber.py localhost
```

### 2. Scan Specific Ports
```bash
python3 banner_grabber.py <target_host> -p 22,80,443
```

Example:
```bash
python3 banner_grabber.py example.com -p 80,443
```

### 3. Custom Vulnerability Database
```bash
python3 banner_grabber.py <target_host> -d /path/to/custom_vulnerabilities.json
```

## Output Interpretation

### Port Status
- **OPEN** - Port is accessible and service responded
- **CLOSED** - Port is not accessible (timeout or connection refused)

### Service Information
- **Service** - Identified service name (ssh, apache, nginx, mysql, etc.)
- **Version** - Extracted version number from banner
- **Banner** - Raw service banner response (truncated in display)

### Vulnerability Status
- **✓ No known vulnerabilities** - Service version is not in vulnerability database
- **⚠️ VULNERABILITIES FOUND** - One or more CVEs matched

## Running Tests
```bash
python3 test_banner_grabber.py
```

## Running Examples
```bash
python3 example_usage.py
```

## Programmatic Usage

```python
from banner_grabber import BannerGrabber

# Create scanner
scanner = BannerGrabber()

# Scan single port
result = scanner.scan_port('localhost', 22)
print(f"Service: {result['service']}")
print(f"Version: {result['version']}")

# Scan multiple ports
results = scanner.scan_host('localhost', ports=[22, 80, 443])

# Generate report
report = scanner.generate_report(results)
print(report)

# Check specific version for vulnerabilities
vulns = scanner.check_vulnerabilities('apache', '2.4.49', 'Server: Apache/2.4.49')
for vuln in vulns:
    print(f"{vuln['cve']}: {vuln['description']}")
```

## Common Use Cases

### 1. Quick Security Check
Check if your server is running vulnerable service versions:
```bash
python3 banner_grabber.py your-server.com
```

### 2. Web Server Scan
Focus on web-related ports:
```bash
python3 banner_grabber.py target.com -p 80,443,8080,8443
```

### 3. Database Server Scan
Check database ports:
```bash
python3 banner_grabber.py db-server.com -p 3306,5432,6379,27017
```

### 4. SSH Server Audit
Check only SSH:
```bash
python3 banner_grabber.py server.com -p 22
```

## Vulnerability Database Format

The `vulnerabilities.json` file uses this structure:

```json
{
  "service_name": [
    {
      "cve": "CVE-2021-XXXXX",
      "version": "1.2.3",
      "description": "Vulnerability description",
      "severity": "critical|high|medium|low"
    },
    {
      "cve": "CVE-2020-XXXXX",
      "keywords": ["keyword1", "keyword2"],
      "description": "Another vulnerability",
      "severity": "high"
    }
  ]
}
```

### Matching Methods:
1. **Version matching** - Exact or prefix match on version string
2. **Keyword matching** - Banner contains specific keywords

## Tips & Best Practices

### For Accurate Results:
- Some services may not respond immediately (timeout set to 3 seconds)
- Firewalls may block banner grabbing attempts
- Some services may not send banners without specific requests

### Security & Ethics:
- ⚠️ **Only scan systems you own or have explicit permission to test**
- Unauthorized port scanning may be illegal in your jurisdiction
- Always follow responsible disclosure practices

### Performance:
- Scanning many ports may take time (3-second timeout per port)
- Use specific port lists instead of scanning all default ports
- Consider network latency when interpreting results

### Extending the Tool:
- Add more services to `vulnerabilities.json`
- Customize version extraction patterns in `extract_version()`
- Add new service identification rules in `_identify_service()`

## Troubleshooting

### No Banners Returned
- Service may not send banner automatically
- Firewall may be blocking connection
- Port may be closed
- Increase timeout if needed (modify source)

### Version Not Extracted
- Banner format may not match regex patterns
- Add custom pattern in `extract_version()` method
- Check `test_banner_grabber.py` for examples

### Vulnerabilities Not Detected
- Version may not be in database
- Update `vulnerabilities.json` with latest CVEs
- Check if version string format matches database entries

## Support & Contribution

Found a bug? Want to add features?
- Report issues on GitHub
- Submit pull requests with improvements
- Share your vulnerability database updates

## References
- [CVE Database](https://cve.mitre.org/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [ExploitDB](https://www.exploit-db.com/)
