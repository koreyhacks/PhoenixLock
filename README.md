# PhoenixLock

PhoenixLock is a powerful IoT device hardening and security auditing tool designed to discover, analyze, and secure IoT devices on your network. Created by koreyhacks_, it helps IT teams identify vulnerable IoT devices, check for default credentials, detect unpatched CVEs, and generate comprehensive hardening checklists.

![2025-03-11 09_39_31-KALI  Running  - Oracle VirtualBox _ 1](https://github.com/user-attachments/assets/4910a360-a1e4-44b7-aff4-d77b400fd9ee)


## Features

- **Device Discovery**: Automatically detect IoT devices (cameras, smart sensors, etc.) on your network
- **Default Credential Testing**: Check devices for commonly used default passwords (ethical use only!)
- **Vulnerability Scanning**: Check for unpatched CVEs via NVD API integration
- **Hardening Checklists**: Generate comprehensive security recommendations for your IT team
- **Report Generation**: Export findings in JSON, CSV, or YAML formats
- **Multi-threaded**: Fast, efficient scanning with configurable thread count

## Installation

### Prerequisites

- Python 3.6+
- Nmap installed on system
- Python dependencies (requirements.txt)

### Steps

1. Clone the repository:
```bash
git clone https://github.com/koreyhacks_/phoenixlock.git
cd phoenixlock
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure Nmap is installed on your system:
   - For Kali Linux/Ubuntu/Debian: `sudo apt install nmap` (pre-installed on Kali)
   - For CentOS/RHEL: `sudo yum install nmap`
   - For Windows: Install from [nmap.org](https://nmap.org/download.html)

## Usage

### Basic Usage

Run a complete scan of your local network:
```bash
sudo python phoenixlock.py --target 192.168.1.0/24
```

### Command-line Options

```
usage: phoenixlock.py [-h] [--target TARGET] [--config CONFIG] [--output OUTPUT]
                [--format {json,csv,yaml}] [--timeout TIMEOUT]
                [--threads THREADS] [--ports PORTS] [--nvd-api-key NVD_API_KEY]
                [--discover] [--check-creds] [--check-vulns]
                [--generate-checklist]

PhoenixLock - IoT Device Hardening Tool
```

### Examples

1. Discover IoT devices only:
```bash
python phoenixlock.py --target 192.168.1.0/24 --discover
```

2. Check for default credentials on discovered devices:
```bash
python phoenixlock.py --target 192.168.1.0/24 --check-creds
```

3. Generate a hardening checklist and export as CSV:
```bash
python phoenixlock.py --target 192.168.1.0/24 --generate-checklist --format csv --output hardening.csv
```

4. Full scan with custom configuration:
```bash
python phoenixlock.py --target 192.168.1.0/24 --config config.json --threads 20 --timeout 10
```

## Configuration

PhoenixLock can be configured using a JSON configuration file. Example:

```json
{
  "scan_timeout": 5,
  "threads": 10,
  "nvd_api_key": "YOUR-NVD-API-KEY-HERE",
  "common_credentials": [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "root", "password": "root"},
    {"username": "user", "password": "user"},
    {"username": "guest", "password": "guest"}
  ],
  "ports_to_scan": [22, 23, 80, 443, 554, 8080, 8443, 9000],
  "user_agent": "PhoenixLock-Scanner/1.0"
}
```

### NVD API Key

For full vulnerability scanning capabilities, it's recommended to obtain an NVD API key (free) from the [National Vulnerability Database](https://nvd.nist.gov/developers/request-an-api-key).

You can:
1. Add it to your config.json file
2. Pass it as a command-line parameter: `--nvd-api-key YOUR_API_KEY`

## Troubleshooting

If you encounter the warning: `Warning: No NVD API key provided. Limited vulnerability checks will be performed.` even after configuring your API key, try one of these approaches:

1. Specify the config file path explicitly:
```bash
python phoenixlock.py --target 192.168.1.0/24 --config /full/path/to/config.json
```

2. Pass the API key directly:
```bash
python phoenixlock.py --target 192.168.1.0/24 --nvd-api-key YOUR_ACTUAL_API_KEY
```

3. Check that your config.json file is properly formatted JSON with no syntax errors

## Ethical Use

This tool is intended for legitimate security auditing by authorized personnel. Always obtain proper authorization before scanning networks that you do not own or administer.

The credential testing feature is designed for identifying security vulnerabilities in your own networks, not for unauthorized access to systems.

## Credits

Created by koreyhacks_
