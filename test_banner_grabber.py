#!/usr/bin/env python3
"""
Test script for banner_grabber.py functionality
"""

import sys
from banner_grabber import BannerGrabber


def test_version_extraction():
    """Test version extraction from various banners."""
    print("Testing version extraction...")
    scanner = BannerGrabber()
    
    test_cases = [
        ('ssh', 'SSH-2.0-OpenSSH_7.1p2 Ubuntu-4ubuntu2.8', 'OpenSSH_7.1'),
        ('apache', 'HTTP/1.1 200 OK\nServer: Apache/2.4.49\n', '2.4.49'),
        ('nginx', 'HTTP/1.1 200 OK\nServer: nginx/1.16.0\n', '1.16.0'),
        ('mysql', 'Welcome to MySQL 5.5.51', '5.5.51'),
    ]
    
    passed = 0
    failed = 0
    
    for service, banner, expected_version in test_cases:
        result = scanner.extract_version(banner, service)
        if expected_version in str(result):
            print(f"  ✓ {service}: Extracted '{result}' (expected '{expected_version}')")
            passed += 1
        else:
            print(f"  ✗ {service}: Got '{result}', expected '{expected_version}'")
            failed += 1
    
    print(f"\nVersion Extraction: {passed} passed, {failed} failed\n")
    return failed == 0


def test_vulnerability_detection():
    """Test vulnerability detection."""
    print("Testing vulnerability detection...")
    scanner = BannerGrabber()
    
    test_cases = [
        ('ssh', 'OpenSSH_7.1', 'SSH-2.0-OpenSSH_7.1p2', 'CVE-2016-0777'),
        ('apache', '2.4.49', 'Server: Apache/2.4.49', 'CVE-2021-41773'),
        ('nginx', '1.16.0', 'Server: nginx/1.16.0', 'CVE-2019-9511'),
    ]
    
    passed = 0
    failed = 0
    
    for service, version, banner, expected_cve in test_cases:
        vulns = scanner.check_vulnerabilities(service, version, banner)
        cve_found = any(expected_cve in v.get('cve', '') for v in vulns)
        
        if cve_found:
            print(f"  ✓ {service} {version}: Found {expected_cve}")
            passed += 1
        else:
            print(f"  ✗ {service} {version}: Did not find {expected_cve}")
            failed += 1
    
    print(f"\nVulnerability Detection: {passed} passed, {failed} failed\n")
    return failed == 0


def test_service_identification():
    """Test service identification."""
    print("Testing service identification...")
    scanner = BannerGrabber()
    
    test_cases = [
        (22, 'SSH-2.0-OpenSSH_7.1p2', 'ssh'),
        (80, 'HTTP/1.1 200 OK\nServer: Apache/2.4.49', 'apache'),
        (80, 'HTTP/1.1 200 OK\nServer: nginx/1.16.0', 'nginx'),
        (3306, 'Welcome to MySQL', 'mysql'),
    ]
    
    passed = 0
    failed = 0
    
    for port, banner, expected_service in test_cases:
        result = scanner._identify_service(port, banner)
        if result == expected_service:
            print(f"  ✓ Port {port}: Identified as '{result}'")
            passed += 1
        else:
            print(f"  ✗ Port {port}: Got '{result}', expected '{expected_service}'")
            failed += 1
    
    print(f"\nService Identification: {passed} passed, {failed} failed\n")
    return failed == 0


def main():
    """Run all tests."""
    print("=" * 60)
    print("Banner Grabber Test Suite")
    print("=" * 60)
    print()
    
    all_passed = True
    
    all_passed &= test_version_extraction()
    all_passed &= test_vulnerability_detection()
    all_passed &= test_service_identification()
    
    print("=" * 60)
    if all_passed:
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
    else:
        print("✗ Some tests failed")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
