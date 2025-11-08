#!/usr/bin/env python3
"""
Example usage of the BannerGrabber class
Demonstrates how to use the scanner programmatically
"""

from banner_grabber import BannerGrabber


def example_basic_scan():
    """Example: Basic scan of localhost"""
    print("\n" + "=" * 60)
    print("EXAMPLE 1: Basic Scan")
    print("=" * 60)
    
    # Create scanner instance
    scanner = BannerGrabber()
    
    # Scan localhost with default ports
    results = scanner.scan_host('localhost', ports=[22, 80, 443])
    
    # Generate and print report
    report = scanner.generate_report(results)
    print(report)


def example_custom_ports():
    """Example: Scan specific ports"""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Scan Specific Ports")
    print("=" * 60)
    
    scanner = BannerGrabber()
    
    # Scan only SSH and HTTP
    custom_ports = [22, 80]
    results = scanner.scan_host('localhost', ports=custom_ports)
    
    print(scanner.generate_report(results))


def example_single_port_scan():
    """Example: Scan a single port and inspect results"""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Single Port Detailed Inspection")
    print("=" * 60)
    
    scanner = BannerGrabber()
    
    # Scan single port
    result = scanner.scan_port('localhost', 22)
    
    print(f"\nPort: {result['port']}")
    print(f"Status: {result['status']}")
    print(f"Service: {result['service']}")
    print(f"Version: {result['version']}")
    print(f"Banner Preview: {result['banner'][:100] if result['banner'] else 'N/A'}...")
    print(f"Vulnerabilities: {len(result['vulnerabilities'])} found")
    
    if result['vulnerabilities']:
        print("\nVulnerability Details:")
        for vuln in result['vulnerabilities']:
            print(f"  - CVE: {vuln.get('cve', 'N/A')}")
            print(f"    Severity: {vuln.get('severity', 'unknown')}")
            print(f"    Description: {vuln.get('description', 'No description')}")


def example_vulnerability_check():
    """Example: Direct vulnerability checking"""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Direct Vulnerability Check")
    print("=" * 60)
    
    scanner = BannerGrabber()
    
    # Check specific service versions
    test_cases = [
        ('apache', '2.4.49', 'Server: Apache/2.4.49'),
        ('ssh', 'OpenSSH_7.1', 'SSH-2.0-OpenSSH_7.1p2'),
        ('nginx', '1.16.0', 'Server: nginx/1.16.0'),
    ]
    
    for service, version, banner in test_cases:
        print(f"\nChecking {service} {version}...")
        vulns = scanner.check_vulnerabilities(service, version, banner)
        
        if vulns:
            print(f"  ⚠️  Found {len(vulns)} vulnerability(ies):")
            for vuln in vulns:
                print(f"    - {vuln.get('cve', 'N/A')}: {vuln.get('description', '')}")
        else:
            print("  ✓ No known vulnerabilities")


def example_version_extraction():
    """Example: Extract versions from banners"""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Version Extraction")
    print("=" * 60)
    
    scanner = BannerGrabber()
    
    banners = [
        ('ssh', 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1'),
        ('apache', 'HTTP/1.1 200 OK\nServer: Apache/2.4.52 (Ubuntu)\nDate: Mon'),
        ('nginx', 'Server: nginx/1.18.0 (Ubuntu)'),
        ('mysql', 'Welcome to MySQL 8.0.32'),
    ]
    
    print("\nExtracting versions from various banners:")
    for service, banner in banners:
        version = scanner.extract_version(banner, service)
        print(f"  {service:10} -> Version: {version if version else 'Not found'}")
        print(f"             Banner: {banner[:60]}...")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("Banner Grabber - Usage Examples")
    print("=" * 60)
    
    # Run examples
    example_basic_scan()
    example_custom_ports()
    example_single_port_scan()
    example_vulnerability_check()
    example_version_extraction()
    
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == '__main__':
    main()
