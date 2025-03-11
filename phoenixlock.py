#!/usr/bin/env python3
"""
PhoenixLock - IoT Device Hardening Tool
A security utility for auditing and securing IoT devices such as cameras and smart sensors.
"""

import argparse
import requests
import socket
import sys
import json
import csv
import time
import concurrent.futures
import ipaddress
from datetime import datetime
import paramiko
import nmap
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

# Configuration
DEFAULT_CONFIG = {
    "scan_timeout": 5,
    "threads": 10,
    "nvd_api_key": "",  # Users should add their own NVD API key
    "common_credentials": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "root", "password": "root"},
        {"username": "user", "password": "user"},
        # Add more common default credentials
    ],
    "ports_to_scan": [22, 23, 80, 443, 554, 8080, 8443, 9000],  # Common IoT device ports
    "user_agent": "PhoenixLock-Scanner/1.0"
}

class IoTSec:
    def __init__(self, config=None):
        """Initialize the IoTSec scanner with configuration."""
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        
        self.nm = nmap.PortScanner()
        self.console = Console()
        
    def discover_devices(self, target_range):
        """Discover IoT devices on the network."""
        console.log(f"[bold blue]Discovering devices in range: {target_range}[/bold blue]")
        
        try:
            # Convert target to valid IP range
            network = ipaddress.ip_network(target_range, strict=False)
            
            # Scan the network for common IoT ports
            port_list = ",".join(map(str, self.config["ports_to_scan"]))
            
            # For larger networks, use ping scan first
            if network.num_addresses > 100:
                console.log("Large network detected, performing ping scan first...")
                self.nm.scan(hosts=target_range, arguments='-sn')
                hosts_list = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
            else:
                hosts_list = [str(ip) for ip in network]
            
            # Scan for services on discovered hosts
            devices = []
            with console.status("[bold green]Scanning for IoT devices...[/bold green]"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
                    future_to_ip = {executor.submit(self._scan_host, str(ip), port_list): str(ip) for ip in hosts_list}
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            device_info = future.result()
                            if device_info:
                                devices.append(device_info)
                                console.log(f"Discovered potential IoT device: {ip}")
                        except Exception as exc:
                            console.log(f"Error scanning {ip}: {exc}")
            
            return devices
        
        except Exception as e:
            console.log(f"[bold red]Error during device discovery: {str(e)}[/bold red]")
            return []
    
    def _scan_host(self, ip, port_list):
        """Scan a single host for IoT services."""
        try:
            # Use nmap to scan for open ports
            self.nm.scan(hosts=ip, ports=port_list, arguments=f'-sS -sV --max-retries 1 --host-timeout {self.config["scan_timeout"]}s')
            
            # Check if host was scanned and has open ports
            if ip in self.nm.all_hosts():
                device_info = {
                    "ip": ip,
                    "hostname": self.nm[ip].hostname() if hasattr(self.nm[ip], 'hostname') else "",
                    "open_ports": [],
                    "device_type": "unknown",
                    "vendor": "unknown",
                    "model": "unknown"
                }
                
                # Check open ports and services
                for proto in self.nm[ip].all_protocols():
                    for port in self.nm[ip][proto].keys():
                        port_info = self.nm[ip][proto][port]
                        service_info = {
                            "port": port,
                            "protocol": proto,
                            "service": port_info['name'],
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', '')
                        }
                        device_info["open_ports"].append(service_info)
                        
                        # Try to determine device type
                        if self._identify_device_type(service_info):
                            device_info["device_type"] = self._identify_device_type(service_info)
                            
                        # Try to detect vendor and model
                        if 'product' in port_info and port_info['product']:
                            device_info["vendor"] = port_info['product'].split()[0] if ' ' in port_info['product'] else port_info['product']
                
                # Only return if the device has open ports and might be an IoT device
                if device_info["open_ports"]:
                    return device_info
            
            return None
        
        except Exception as e:
            console.log(f"Error scanning {ip}: {str(e)}")
            return None
            
    def _identify_device_type(self, service_info):
        """Try to identify the device type based on service information."""
        service = service_info["service"].lower()
        product = service_info["product"].lower()
        
        # Check for common IoT device indicators
        if any(cam in product for cam in ["cam", "ipcam", "webcam", "hikvision", "dahua"]):
            return "camera"
        elif "rtsp" in service or service_info["port"] == 554:
            return "camera"
        elif any(sensor in product for sensor in ["sensor", "nest", "hue", "iot"]):
            return "sensor"
        elif service == "telnet" or service == "ssh":
            return "network_device"  # Could be a router, switch, or other IoT device
        elif "http" in service and service_info["port"] in [80, 8080, 443, 8443]:
            # Need to do additional checks for web interface
            return "smart_device"
            
        return "unknown"
    
    def check_default_credentials(self, devices):
        """Check for default credentials on the discovered devices."""
        console.log("[bold blue]Checking devices for default credentials[/bold blue]")
        
        results = []
        with console.status("[bold yellow]Testing default credentials...[/bold yellow]"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
                future_to_device = {executor.submit(self._check_device_credentials, device): device for device in devices}
                for future in concurrent.futures.as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        result = future.result()
                        if result["vulnerable_services"]:
                            console.log(f"[bold red]Found default credentials on {device['ip']}[/bold red]")
                        results.append(result)
                    except Exception as exc:
                        console.log(f"Error checking credentials for {device['ip']}: {exc}")
        
        return results
    
    def _check_device_credentials(self, device):
        """Check a single device for default credentials."""
        result = {
            "ip": device["ip"],
            "device_type": device["device_type"],
            "vulnerable_services": []
        }
        
        for port_info in device["open_ports"]:
            port = port_info["port"]
            service = port_info["service"]
            
            # Check SSH
            if service == "ssh" and port == 22:
                ssh_result = self._check_ssh_credentials(device["ip"], port)
                if ssh_result:
                    result["vulnerable_services"].append(ssh_result)
            
            # Check Telnet
            elif service == "telnet" and port == 23:
                telnet_result = self._check_telnet_credentials(device["ip"], port)
                if telnet_result:
                    result["vulnerable_services"].append(telnet_result)
            
            # Check Web services (HTTP/HTTPS)
            elif service in ["http", "https"] and port in [80, 443, 8080, 8443]:
                web_result = self._check_web_credentials(device["ip"], port, service == "https")
                if web_result:
                    result["vulnerable_services"].append(web_result)
        
        return result
    
    def _check_ssh_credentials(self, ip, port):
        """Check SSH service for default credentials."""
        for cred in self.config["common_credentials"]:
            username = cred["username"]
            password = cred["password"]
            
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Attempt to connect with timeout
                ssh_client.connect(
                    hostname=ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.config["scan_timeout"],
                    banner_timeout=self.config["scan_timeout"],
                    auth_timeout=self.config["scan_timeout"]
                )
                
                # If connection succeeds, we found working credentials
                ssh_client.close()
                return {
                    "service": "ssh",
                    "port": port,
                    "username": username,
                    "password": password
                }
            
            except (paramiko.AuthenticationException, paramiko.SSHException):
                # Authentication failed or other SSH error
                continue
            except Exception as e:
                # Connection error or timeout
                break
        
        return None
    
    def _check_telnet_credentials(self, ip, port):
        """Placeholder for telnet credential checking."""
        # Note: This is a simplified version. Real implementation would 
        # require a telnet library or socket connection with proper prompt handling
        return None
    
    def _check_web_credentials(self, ip, port, is_https):
        """Check web service for default credentials."""
        # Very basic check for common login pages and default credentials
        # A complete solution would need to handle different login forms, authentication methods, etc.
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{ip}:{port}"
        
        try:
            # First try to get the login page
            login_paths = ["/login", "/admin", "/system", "/device"]
            
            for path in login_paths:
                full_url = f"{url}{path}"
                response = requests.get(
                    full_url, 
                    timeout=self.config["scan_timeout"],
                    verify=False,  # Skip SSL verification
                    headers={"User-Agent": self.config["user_agent"]}
                )
                
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["login", "username", "password"]):
                    # Found potential login page, try credentials
                    for cred in self.config["common_credentials"]:
                        username = cred["username"]
                        password = cred["password"]
                        
                        # This is a simplified approach - real implementation would need 
                        # to analyze the form and submit with proper parameters
                        data = {
                            "username": username,
                            "password": password,
                            "login": "Login"
                        }
                        
                        login_response = requests.post(
                            full_url,
                            data=data,
                            timeout=self.config["scan_timeout"],
                            verify=False,
                            headers={"User-Agent": self.config["user_agent"]}
                        )
                        
                        # Check if login was successful (this is a simple heuristic)
                        if login_response.status_code == 200 and "login" not in login_response.url.lower():
                            return {
                                "service": "web",
                                "port": port,
                                "path": path,
                                "username": username,
                                "password": password
                            }
        
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def check_vulnerabilities(self, devices):
        """Check devices for known vulnerabilities using NVD API."""
        console.log("[bold blue]Checking devices for known vulnerabilities[/bold blue]")
        
        if not self.config["nvd_api_key"]:
            console.log("[bold yellow]Warning: No NVD API key provided. Limited vulnerability checks will be performed.[/bold yellow]")
        
        results = []
        with console.status("[bold yellow]Checking for CVEs...[/bold yellow]"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
                future_to_device = {executor.submit(self._check_device_vulnerabilities, device): device for device in devices}
                for future in concurrent.futures.as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        result = future.result()
                        if result["vulnerabilities"]:
                            console.log(f"[bold red]Found {len(result['vulnerabilities'])} potential vulnerabilities for {device['ip']}[/bold red]")
                        results.append(result)
                    except Exception as exc:
                        console.log(f"Error checking vulnerabilities for {device['ip']}: {exc}")
        
        return results
    
    def _check_device_vulnerabilities(self, device):
        """Check a single device for known vulnerabilities."""
        result = {
            "ip": device["ip"],
            "device_type": device["device_type"],
            "vulnerabilities": []
        }
        
        # Check each service running on the device
        for port_info in device["open_ports"]:
            if port_info.get("product") and port_info.get("version"):
                product = port_info["product"]
                version = port_info["version"]
                
                # Query NVD for this product and version
                cve_list = self._query_nvd_for_cves(product, version)
                
                for cve in cve_list:
                    vulnerability = {
                        "service": port_info["service"],
                        "port": port_info["port"],
                        "product": product,
                        "version": version,
                        "cve_id": cve["cve_id"],
                        "description": cve["description"],
                        "cvss_score": cve["cvss_score"],
                        "severity": cve["severity"],
                        "references": cve["references"]
                    }
                    result["vulnerabilities"].append(vulnerability)
        
        return result
    
    def _query_nvd_for_cves(self, product, version):
        """Query the NVD API for CVEs related to the product and version."""
        cve_list = []
        
        try:
            # Convert product name to a search-friendly format
            product_search = product.lower().replace(" ", "+")
            
            # Construct NVD API URL
            base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
            url = f"{base_url}?keyword={product_search}+{version}&resultsPerPage=100"
            
            headers = {
                "User-Agent": self.config["user_agent"]
            }
            
            # Add API key if provided
            if self.config["nvd_api_key"]:
                headers["apiKey"] = self.config["nvd_api_key"]
            
            # Make the API request
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Process the results
                if "result" in data and "CVE_Items" in data["result"]:
                    for item in data["result"]["CVE_Items"]:
                        cve_id = item["cve"]["CVE_data_meta"]["ID"]
                        
                        # Get description
                        description = ""
                        if "description" in item["cve"] and "description_data" in item["cve"]["description"]:
                            for desc in item["cve"]["description"]["description_data"]:
                                if desc["lang"] == "en":
                                    description = desc["value"]
                                    break
                        
                        # Get CVSS score and severity
                        cvss_score = 0
                        severity = "UNKNOWN"
                        
                        if "impact" in item:
                            if "baseMetricV3" in item["impact"]:
                                cvss_score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                                severity = item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                            elif "baseMetricV2" in item["impact"]:
                                cvss_score = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                                severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
                        
                        # Get references
                        references = []
                        if "references" in item["cve"] and "reference_data" in item["cve"]["references"]:
                            for ref in item["cve"]["references"]["reference_data"]:
                                references.append(ref["url"])
                        
                        cve_info = {
                            "cve_id": cve_id,
                            "description": description,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "references": references[:5]  # Limit to 5 references
                        }
                        
                        cve_list.append(cve_info)
            
            # NVD API has rate limits, sleep briefly
            time.sleep(1)
            
        except Exception as e:
            console.log(f"Error querying NVD API: {str(e)}")
        
        return cve_list
    
    def generate_hardening_checklist(self, scan_results):
        """Generate a hardening checklist based on scan results."""
        console.log("[bold blue]Generating hardening checklist[/bold blue]")
        
        # Extract scan data
        devices = scan_results.get("devices", [])
        credential_results = scan_results.get("credential_results", [])
        vulnerability_results = scan_results.get("vulnerability_results", [])
        
        # Track issues by device
        device_issues = {}
        
        # Process credential issues
        for cred_result in credential_results:
            ip = cred_result["ip"]
            if ip not in device_issues:
                device_issues[ip] = {
                    "ip": ip,
                    "device_type": cred_result["device_type"],
                    "default_credentials": [],
                    "vulnerabilities": [],
                    "open_ports": []
                }
            
            for service in cred_result["vulnerable_services"]:
                device_issues[ip]["default_credentials"].append(service)
        
        # Process vulnerability issues
        for vuln_result in vulnerability_results:
            ip = vuln_result["ip"]
            if ip not in device_issues:
                device_issues[ip] = {
                    "ip": ip,
                    "device_type": vuln_result["device_type"],
                    "default_credentials": [],
                    "vulnerabilities": [],
                    "open_ports": []
                }
            
            for vuln in vuln_result["vulnerabilities"]:
                device_issues[ip]["vulnerabilities"].append(vuln)
        
        # Process open ports
        for device in devices:
            ip = device["ip"]
            if ip not in device_issues:
                device_issues[ip] = {
                    "ip": ip,
                    "device_type": device["device_type"],
                    "default_credentials": [],
                    "vulnerabilities": [],
                    "open_ports": []
                }
            
            for port_info in device["open_ports"]:
                device_issues[ip]["open_ports"].append(port_info)
        
        # Generate checklist items
        checklist = {
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_devices": len(devices),
                "devices_with_default_credentials": sum(1 for d in device_issues.values() if d["default_credentials"]),
                "devices_with_vulnerabilities": sum(1 for d in device_issues.values() if d["vulnerabilities"]),
                "total_vulnerabilities": sum(len(d["vulnerabilities"]) for d in device_issues.values())
            },
            "device_hardening": []
        }
        
        # Create checklist for each device with issues
        for ip, issues in device_issues.items():
            device_checklist = {
                "ip": ip,
                "device_type": issues["device_type"],
                "checklist_items": []
            }
            
            # Default credentials items
            if issues["default_credentials"]:
                for cred in issues["default_credentials"]:
                    item = {
                        "priority": "HIGH",
                        "category": "Authentication",
                        "issue": f"Default credentials found for {cred['service']} on port {cred['port']}",
                        "recommendation": f"Change default username '{cred['username']}' and password on {cred['service']}"
                    }
                    device_checklist["checklist_items"].append(item)
            
            # Vulnerability items
            if issues["vulnerabilities"]:
                for vuln in issues["vulnerabilities"]:
                    item = {
                        "priority": vuln["severity"],
                        "category": "Software",
                        "issue": f"Vulnerable {vuln['product']} {vuln['version']} - {vuln['cve_id']}",
                        "recommendation": f"Update {vuln['product']} to patch {vuln['cve_id']} (CVSS: {vuln['cvss_score']})",
                        "details": vuln["description"]
                    }
                    device_checklist["checklist_items"].append(item)
            
            # Open ports recommendations
            risky_ports = {23: "Telnet", 21: "FTP", 25: "SMTP", 53: "DNS", 161: "SNMP"}
            for port_info in issues["open_ports"]:
                port = port_info["port"]
                service = port_info["service"]
                
                if port in risky_ports:
                    item = {
                        "priority": "MEDIUM",
                        "category": "Network",
                        "issue": f"Potentially risky service {risky_ports[port]} open on port {port}",
                        "recommendation": f"Disable {risky_ports[port]} if not required or replace with secure alternative"
                    }
                    device_checklist["checklist_items"].append(item)
                
                # Check for unencrypted services
                if service == "http" and port in [80, 8080]:
                    item = {
                        "priority": "MEDIUM",
                        "category": "Encryption",
                        "issue": f"Unencrypted HTTP service on port {port}",
                        "recommendation": "Replace with HTTPS or enable TLS encryption"
                    }
                    device_checklist["checklist_items"].append(item)
            
            # General recommendations for all devices
            general_items = [
                {
                    "priority": "MEDIUM",
                    "category": "Firmware",
                    "issue": "Potential outdated firmware",
                    "recommendation": "Check and update to latest firmware version from manufacturer"
                },
                {
                    "priority": "MEDIUM",
                    "category": "Access Control",
                    "issue": "Potential excessive network exposure",
                    "recommendation": "Implement network segmentation or VLAN for IoT devices"
                },
                {
                    "priority": "LOW",
                    "category": "Monitoring",
                    "issue": "Lack of monitoring",
                    "recommendation": "Implement logging and monitoring for unusual behavior"
                }
            ]
            
            # Add general items (only if there are other issues)
            if device_checklist["checklist_items"]:
                device_checklist["checklist_items"].extend(general_items)
                
                # Sort by priority
                priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                device_checklist["checklist_items"].sort(key=lambda x: priority_order.get(x["priority"], 3))
                
                checklist["device_hardening"].append(device_checklist)
        
        return checklist
    
    def export_results(self, scan_results, output_format="json", output_file=None):
        """Export scan results to the specified format."""
        # Format scan date for filename if no output file specified
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"iotsec_scan_{timestamp}.{output_format}"
        
        try:
            if output_format == "json":
                with open(output_file, 'w') as f:
                    json.dump(scan_results, f, indent=2)
            
            elif output_format == "csv":
                # Flatten the data structure for CSV
                rows = []
                
                # Process devices
                for device in scan_results.get("devices", []):
                    for port_info in device.get("open_ports", []):
                        row = {
                            "ip": device["ip"],
                            "device_type": device["device_type"],
                            "port": port_info["port"],
                            "service": port_info["service"],
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "default_credentials": "No",
                            "vulnerability_count": 0
                        }
                        rows.append(row)
                
                # Process credential findings
                for cred_result in scan_results.get("credential_results", []):
                    ip = cred_result["ip"]
                    for service in cred_result.get("vulnerable_services", []):
                        # Find matching row
                        for row in rows:
                            if row["ip"] == ip and str(row["port"]) == str(service["port"]):
                                row["default_credentials"] = "Yes"
                                break
                
                # Process vulnerability findings
                for vuln_result in scan_results.get("vulnerability_results", []):
                    ip = vuln_result["ip"]
                    # Count vulnerabilities per service
                    vuln_counts = {}
                    for vuln in vuln_result.get("vulnerabilities", []):
                        key = f"{vuln['port']}:{vuln['service']}"
                        vuln_counts[key] = vuln_counts.get(key, 0) + 1
                    
                    # Update matching rows
                    for row in rows:
                        if row["ip"] == ip:
                            key = f"{row['port']}:{row['service']}"
                            if key in vuln_counts:
                                row["vulnerability_count"] = vuln_counts[key]
                
                # Write to CSV
                if rows:
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                        writer.writeheader()
                        writer.writerows(rows)
            
            elif output_format == "yaml":
                with open(output_file, 'w') as f:
                    yaml.dump(scan_results, f, default_flow_style=False)
            
            console.log(f"[bold green]Results exported to {output_file}[/bold green]")
            return output_file
        
        except Exception as e:
            console.log(f"[bold red]Error exporting results: {str(e)}[/bold red]")
            return None
    
    def display_results_summary(self, scan_results):
        """Display a summary of scan results in the console."""
        devices = scan_results.get("devices", [])
        credential_results = scan_results.get("credential_results", [])
        vulnerability_results = scan_results.get("vulnerability_results", [])
        
        # Create summary table
        table = Table(title="IoTSec Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Details", style="yellow")
        
        # Device stats
        device_count = len(devices)
        device_types = {}
        for device in devices:
            device_type = device["device_type"]
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        device_details = ", ".join([f"{count} {device_type}" for device_type, count in device_types.items()])
        table.add_row("Devices Discovered", str(device_count), device_details or "None")
        
        # Credential stats
        vulnerable_creds_count = sum(1 for result in credential_results if result["vulnerable_services"])
        cred_services = {}
        for result in credential_results:
            for service in result["vulnerable_services"]:
                service_name = service["service"]
                cred_services[service_name] = cred_services.get(service_name, 0) + 1
        
        cred_details = ", ".join([f"{count} {service}" for service, count in cred_services.items()])
        table.add_row("Default Credentials", str(vulnerable_creds_count), cred_details or "None")
        
        # Vulnerability stats
        vuln_count = sum(len(result["vulnerabilities"]) for result in vulnerability_results)
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in vulnerability_results:
            for vuln in result["vulnerabilities"]:
                severity = vuln["severity"]
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        vuln_details = ", ".join([f"{count} {severity.lower()}" for severity, count in severity_counts.items() if count > 0])
        table.add_row("Vulnerabilities", str(vuln_count), vuln_details or "None")
        
        console.print(table)
        
        # If issues found, show more details
        if vulnerable_creds_count > 0:
            console.print("\n[bold red]Default Credentials Found:[/bold red]")
            cred_table = Table()
            cred_table.add_column("IP Address", style="cyan")
            cred_table.add_column("Service", style="yellow")
            cred_table.add_column("Port", style="green")
            cred_table.add_column("Username", style="yellow")
            cred_table.add_column("Password", style="red")
            
            for result in credential_results:
                for service in result["vulnerable_services"]:
                    cred_table.add_row(
                        result["ip"],
                        service["service"],
                        str(service["port"]),
                        service["username"],
                        service["password"]
                    )
            
            console.print(cred_table)
        
        if vuln_count > 0:
            console.print("\n[bold red]Critical Vulnerabilities:[/bold red]")
            vuln_table = Table()
            vuln_table.add_column("IP Address", style="cyan")
            vuln_table.add_column("Product", style="yellow")
            vuln_table.add_column("CVE", style="green")
            vuln_table.add_column("CVSS", style="red")
            
            # Only show high severity vulns in the summary
            for result in vulnerability_results:
                for vuln in result["vulnerabilities"]:
                    if vuln["severity"] == "HIGH" or vuln["cvss_score"] >= 7.0:
                        vuln_table.add_row(
                            result["ip"],
                            f"{vuln['product']} {vuln['version']}",
                            vuln["cve_id"],
                            str(vuln["cvss_score"])
                        )
            
            console.print(vuln_table)

def main():
    """Main entry point for the IoTSec tool."""
    parser = argparse.ArgumentParser(description="PhoenixLock - IoT Device Hardening Tool")
    
    # Main arguments
    parser.add_argument("--target", "-t", help="Target IP range (CIDR notation, e.g., 192.168.1.0/24)")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--format", "-f", choices=["json", "csv", "yaml"], default="json",
                        help="Output format (default: json)")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--timeout", type=int, default=5, help="Scan timeout in seconds (default: 5)")
    scan_group.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    scan_group.add_argument("--ports", help="Comma-separated list of ports to scan")
    scan_group.add_argument("--nvd-api-key", help="NVD API key for vulnerability checks")
    
    # Actions
    action_group = parser.add_argument_group("Actions")
    action_group.add_argument("--discover", action="store_true", help="Discover IoT devices only")
    action_group.add_argument("--check-creds", action="store_true", help="Check for default credentials")
    action_group.add_argument("--check-vulns", action="store_true", help="Check for vulnerabilities")
    action_group.add_argument("--generate-checklist", action="store_true", help="Generate hardening checklist")
    
    args = parser.parse_args()
    
    # Display PhoenixLock text-based banner with fire effect
    phoenixlock_banner = """
[bold #FFDD00]██████╗ ██╗  ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗██╗      ██████╗  ██████╗██╗  ██╗[/bold #FFDD00]
[bold #FFBB00]██╔══██╗██║  ██║██╔═══██╗██╔════╝████╗  ██║██║╚██╗██╔╝██║     ██╔═══██╗██╔════╝██║ ██╔╝[/bold #FFBB00]
[bold #FF9900]██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║██║ ╚███╔╝ ██║     ██║   ██║██║     █████╔╝ [/bold #FF9900]
[bold #FF7700]██╔═══╝ ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ ██║     ██║   ██║██║     ██╔═██╗ [/bold #FF7700]
[bold #FF5500]██║     ██║  ██║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗███████╗╚██████╔╝╚██████╗██║  ██╗[/bold #FF5500]
[bold #FF3300]╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝[/bold #FF3300]

[bold #00CCCC]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold #00CCCC]
[bold #00CCCC]                  IoT Device Hardening & Security Tool v1.0                    [/bold #00CCCC]
[bold #FF5500]                              By koreyhacks_                                   [/bold #FF5500]
[bold #00CCCC]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold #00CCCC]
    """
    console.print(phoenixlock_banner)
    console.print()
    
    # Load configuration
    config = DEFAULT_CONFIG.copy()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            console.log(f"[bold red]Error loading configuration: {str(e)}[/bold red]")
    
    # Override config with command line arguments
    if args.timeout:
        config["scan_timeout"] = args.timeout
    if args.threads:
        config["threads"] = args.threads
    if args.ports:
        config["ports_to_scan"] = [int(p) for p in args.ports.split(",")]
    if args.nvd_api_key:
        config["nvd_api_key"] = args.nvd_api_key
    
    # Initialize scanner
    scanner = IoTSec(config)
    
    # Check if target is specified
    if not args.target:
        console.log("[bold red]Error: Target IP range is required. Use --target option.[/bold red]")
        return
    
    # Determine actions to take
    actions = {
        "discover": args.discover or not (args.check_creds or args.check_vulns or args.generate_checklist),
        "check_creds": args.check_creds or not (args.discover or args.check_vulns or args.generate_checklist),
        "check_vulns": args.check_vulns or not (args.discover or args.check_creds or args.generate_checklist),
        "generate_checklist": args.generate_checklist or not (args.discover or args.check_creds or args.check_vulns)
    }
    
    # If no specific actions are chosen, run all
    if not any([args.discover, args.check_creds, args.check_vulns, args.generate_checklist]):
        for key in actions:
            actions[key] = True
    
    # Run the scan
    scan_results = {}
    
    # Step 1: Discover devices
    if actions["discover"]:
        console.log("[bold blue]Step 1: Discovering IoT devices[/bold blue]")
        devices = scanner.discover_devices(args.target)
        scan_results["devices"] = devices
        
        if not devices:
            console.log("[bold yellow]No IoT devices discovered in the target range.[/bold yellow]")
            return
        else:
            console.log(f"[bold green]Discovered {len(devices)} potential IoT devices.[/bold green]")
    
    # Step 2: Check default credentials
    if actions["check_creds"] and "devices" in scan_results:
        console.log("[bold blue]Step 2: Checking for default credentials[/bold blue]")
        credential_results = scanner.check_default_credentials(scan_results["devices"])
        scan_results["credential_results"] = credential_results
        
        # Count vulnerable devices
        vulnerable_count = sum(1 for result in credential_results if result["vulnerable_services"])
        if vulnerable_count > 0:
            console.log(f"[bold red]Found {vulnerable_count} devices with default credentials.[/bold red]")
        else:
            console.log("[bold green]No devices with default credentials found.[/bold green]")
    
    # Step 3: Check for vulnerabilities
    if actions["check_vulns"] and "devices" in scan_results:
        console.log("[bold blue]Step 3: Checking for vulnerabilities[/bold blue]")
        vulnerability_results = scanner.check_vulnerabilities(scan_results["devices"])
        scan_results["vulnerability_results"] = vulnerability_results
        
        # Count vulnerabilities
        vuln_count = sum(len(result["vulnerabilities"]) for result in vulnerability_results)
        if vuln_count > 0:
            console.log(f"[bold red]Found {vuln_count} potential vulnerabilities.[/bold red]")
        else:
            console.log("[bold green]No vulnerabilities found.[/bold green]")
    
    # Step 4: Generate hardening checklist
    if actions["generate_checklist"] and "devices" in scan_results:
        console.log("[bold blue]Step 4: Generating hardening checklist[/bold blue]")
        checklist = scanner.generate_hardening_checklist(scan_results)
        scan_results["hardening_checklist"] = checklist
        
        console.log(f"[bold green]Generated hardening checklist with {len(checklist['device_hardening'])} devices.[/bold green]")
    
    # Display results summary
    scanner.display_results_summary(scan_results)
    
    # Export results
    if args.output or args.format:
        scanner.export_results(scan_results, args.format, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
