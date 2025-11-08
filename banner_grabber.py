#!/usr/bin/env python3
"""
Service Banner Grabber - A basic scanner that connects to open ports
and attempts to grab service banners (version information) to check
against a local list of known vulnerabilities.
"""

import socket
import re
import json
import sys
from typing import Dict, List, Tuple, Optional


class BannerGrabber:
    """Scanner that grabs service banners and checks for vulnerabilities."""
    
    # Default ports to scan
    DEFAULT_PORTS = [22, 23, 80, 443, 8080, 3306, 5432, 6379]
    
    # Common HTTP request for web servers
    HTTP_REQUEST = b"HEAD / HTTP/1.0\r\n\r\n"
    
    def __init__(self, vulnerabilities_db: str = "vulnerabilities.json"):
        """
        Initialize the banner grabber.
        
        Args:
            vulnerabilities_db: Path to the vulnerabilities database JSON file
        """
        self.vulnerabilities = self._load_vulnerabilities(vulnerabilities_db)
    
    def _load_vulnerabilities(self, db_path: str) -> Dict:
        """
        Load vulnerabilities database from JSON file.
        
        Args:
            db_path: Path to the vulnerabilities JSON file
            
        Returns:
            Dictionary containing vulnerability information
        """
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: Vulnerabilities database '{db_path}' not found. Using empty database.")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing vulnerabilities database: {e}")
            return {}
    
    def grab_banner(self, host: str, port: int, timeout: int = 3) -> Optional[str]:
        """
        Connect to a host:port and attempt to grab the service banner.
        
        Args:
            host: Target host IP or hostname
            port: Target port number
            timeout: Connection timeout in seconds
            
        Returns:
            Banner string if successful, None otherwise
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to the target
            sock.connect((host, port))
            
            # For HTTP/HTTPS ports, send HTTP request
            if port in [80, 443, 8080]:
                sock.send(self.HTTP_REQUEST)
            
            # Receive banner
            banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            print(f"Error grabbing banner from {host}:{port} - {e}")
            return None
    
    def extract_version(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version information from a banner.
        
        Args:
            banner: The service banner string
            service: The service name (e.g., 'ssh', 'apache', 'nginx')
            
        Returns:
            Version string if found, None otherwise
        """
        # Common version patterns
        patterns = {
            'ssh': r'SSH-[\d.]+-(OpenSSH[_\d.]+)',
            'apache': r'Apache/([\d.]+)',
            'nginx': r'nginx/([\d.]+)',
            'mysql': r'MySQL\s+([\d.]+)',
            'ftp': r'FTP.*?([\d.]+)',
            'telnet': r'Telnet.*?([\d.]+)',
        }
        
        # Try specific pattern for the service
        if service.lower() in patterns:
            match = re.search(patterns[service.lower()], banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Generic version pattern as fallback
        generic_pattern = r'(?:version|v)[:\s]*([\d.]+)'
        match = re.search(generic_pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return None
    
    def check_vulnerabilities(self, service: str, version: str, banner: str) -> List[Dict]:
        """
        Check if a service version has known vulnerabilities.
        
        Args:
            service: Service name
            version: Service version
            banner: Full banner string
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities_found = []
        
        # Check if service exists in vulnerability database
        if service not in self.vulnerabilities:
            return vulnerabilities_found
        
        service_vulns = self.vulnerabilities[service]
        
        # Check each vulnerability entry
        for vuln in service_vulns:
            # Check if version matches vulnerable version
            if 'version' in vuln and version:
                if version == vuln['version'] or version.startswith(vuln['version']):
                    vulnerabilities_found.append(vuln)
            
            # Check if banner contains vulnerability keywords
            elif 'keywords' in vuln:
                for keyword in vuln['keywords']:
                    if keyword.lower() in banner.lower():
                        vulnerabilities_found.append(vuln)
                        break
        
        return vulnerabilities_found
    
    def scan_port(self, host: str, port: int) -> Dict:
        """
        Scan a single port and check for vulnerabilities.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Dictionary with scan results
        """
        result = {
            'host': host,
            'port': port,
            'status': 'closed',
            'banner': None,
            'service': None,
            'version': None,
            'vulnerabilities': []
        }
        
        banner = self.grab_banner(host, port)
        
        if banner:
            result['status'] = 'open'
            result['banner'] = banner
            
            # Identify service
            service = self._identify_service(port, banner)
            result['service'] = service
            
            # Extract version
            if service:
                version = self.extract_version(banner, service)
                result['version'] = version
                
                # Check vulnerabilities
                vulns = self.check_vulnerabilities(service, version, banner)
                result['vulnerabilities'] = vulns
        
        return result
    
    def _identify_service(self, port: int, banner: str) -> Optional[str]:
        """
        Identify the service based on port and banner.
        
        Args:
            port: Port number
            banner: Banner string
            
        Returns:
            Service name
        """
        # Port-based identification
        port_services = {
            22: 'ssh',
            23: 'telnet',
            80: 'http',
            443: 'https',
            8080: 'http',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis'
        }
        
        # Banner-based identification
        if 'SSH' in banner.upper():
            return 'ssh'
        elif 'HTTP' in banner.upper():
            if 'Apache' in banner:
                return 'apache'
            elif 'nginx' in banner:
                return 'nginx'
            return 'http'
        elif 'FTP' in banner.upper():
            return 'ftp'
        elif 'MySQL' in banner:
            return 'mysql'
        elif 'PostgreSQL' in banner:
            return 'postgresql'
        
        # Fallback to port-based
        return port_services.get(port, 'unknown')
    
    def scan_host(self, host: str, ports: List[int] = None) -> List[Dict]:
        """
        Scan multiple ports on a host.
        
        Args:
            host: Target host
            ports: List of ports to scan (uses DEFAULT_PORTS if None)
            
        Returns:
            List of scan results
        """
        if ports is None:
            ports = self.DEFAULT_PORTS
        
        results = []
        print(f"\nScanning {host}...")
        print("=" * 60)
        
        for port in ports:
            result = self.scan_port(host, port)
            results.append(result)
            
            # Display results
            if result['status'] == 'open':
                print(f"\n[+] Port {port} is OPEN")
                print(f"    Service: {result['service']}")
                if result['version']:
                    print(f"    Version: {result['version']}")
                print(f"    Banner: {result['banner'][:100]}...")
                
                if result['vulnerabilities']:
                    print(f"    ⚠️  VULNERABILITIES FOUND: {len(result['vulnerabilities'])}")
                    for vuln in result['vulnerabilities']:
                        print(f"        - {vuln.get('cve', 'N/A')}: {vuln.get('description', 'No description')}")
                else:
                    print(f"    ✓ No known vulnerabilities")
        
        return results
    
    def generate_report(self, results: List[Dict]) -> str:
        """
        Generate a summary report of scan results.
        
        Args:
            results: List of scan results
            
        Returns:
            Report string
        """
        report_lines = ["\n" + "=" * 60, "SCAN SUMMARY", "=" * 60]
        
        open_ports = [r for r in results if r['status'] == 'open']
        vulnerable_ports = [r for r in results if r['vulnerabilities']]
        
        report_lines.append(f"\nTotal Ports Scanned: {len(results)}")
        report_lines.append(f"Open Ports: {len(open_ports)}")
        report_lines.append(f"Ports with Vulnerabilities: {len(vulnerable_ports)}")
        
        if vulnerable_ports:
            report_lines.append("\n⚠️  VULNERABLE SERVICES:")
            for result in vulnerable_ports:
                report_lines.append(f"\n  Port {result['port']} - {result['service']}")
                for vuln in result['vulnerabilities']:
                    report_lines.append(f"    - {vuln.get('cve', 'N/A')}: {vuln.get('description', '')}")
        
        report_lines.append("\n" + "=" * 60)
        return "\n".join(report_lines)


def main():
    """Main entry point for the banner grabber."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Service Banner Grabber - Scan ports and check for vulnerabilities'
    )
    parser.add_argument('host', help='Target host IP or hostname')
    parser.add_argument(
        '-p', '--ports',
        help='Comma-separated list of ports to scan (e.g., 22,80,443)',
        default=None
    )
    parser.add_argument(
        '-d', '--database',
        help='Path to vulnerabilities database JSON file',
        default='vulnerabilities.json'
    )
    
    args = parser.parse_args()
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Ports must be comma-separated integers")
            sys.exit(1)
    
    # Create scanner and run scan
    scanner = BannerGrabber(args.database)
    results = scanner.scan_host(args.host, ports)
    
    # Display summary report
    print(scanner.generate_report(results))


if __name__ == '__main__':
    main()
