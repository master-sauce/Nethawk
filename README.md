
# 🔍 NetHawk: Advanced Network Monitoring & IP Intelligence Tool

NetHawk is a powerful dual-purpose security tool designed for real-time network monitoring and comprehensive IP intelligence gathering. Built in Go for cross-platform compatibility, it's perfect for incident response, malware analysis, and threat hunting.

## 🚀 Installation

### Option 1: Quick Install (Recommended)

#### Linux / macOS
```bash
curl -fsSL https://raw.githubusercontent.com/master-sauce/Nethawk/main/install.sh | bash
```

#### Windows
```powershell
irm https://raw.githubusercontent.com/master-sauce/Nethawk/main/install.ps1 | iex
```

### Option 2: Build from Source
```bash
# Prerequisites: Go installed
git clone https://github.com/master-sauce/Nethawk.git
cd Nethawk
go build -o nethawk
```

### Uninstall
Run the same installation commands again to uninstall NetHawk.

## 📋 System Requirements

- **Operating Systems**: Windows, Linux, macOS
- **Privileges**: Administrator/root privileges required for network monitoring
- **Dependencies**: None (single binary deployment)

## 🔧 Usage

NetHawk operates in two distinct modes:

### Network Monitor Mode (`mon`)
Monitor network connections of specific processes or all processes:

```bash
# Monitor a specific process
nethawk mon -p chrome -o net.log

# Monitor all processes (generates extensive data)
nethawk mon --all -s 5

# Options:
# --process, -p <name>  Process name to monitor
# --all                 Monitor all running processes
# --output, -o <path>   Log network activity to file
# --sleep, -s <seconds> Seconds between updates (default: 2)
```

### IP Analyzer Mode (`chk`)
Analyze IP addresses from log files:

```bash
# Basic analysis
nethawk chk -f access.log -o report.txt

# With API integrations
nethawk chk -f access.log -o report.txt -t <ipinfo_token> -a <abuseipdb_key>

# Options:
# --logfile, -f <path>   Log file to analyze (required)
# --output, -o <path>    Save results to file
# --token, -t <string>   ipinfo.io API token
# --abuseipdb, -a <string> AbuseIPDB API key (or path to file containing key)
```

## 🌟 Key Features

### Network Monitoring
- **Real-time Connection Tracking**: Monitor TCP/UDP connections for specific processes
- **Cross-platform Support**: Works on Windows (netstat), Linux (netstat), and macOS (lsof)
- **Process Discovery**: Automatically finds all PIDs for target processes
- **Intelligent Filtering**: Filters network output to show only relevant connections
- **Timestamped Logging**: Critical for forensic analysis and timeline creation

### IP Intelligence
- **Universal Log Parsing**: Works with any log format (Apache, Nginx, firewalls)
- **Deduplication**: Focuses on unique public IP addresses only
- **Geolocation Data**: Provides location, ISP, and organization information
- **Threat Intelligence**: Integrates with ipinfo.io and AbuseIPDB APIs
- **Risk Scoring**: Visual indicators (🔴 HIGH 🟡 MODERATE ✅ CLEAN)
- **Suspicious Activity Flags**: Automatically identifies VPNs, proxies, cloud hosting, and high-risk countries

## 🔍 Advanced Features

### API Integration
- **ipinfo.io**: Comprehensive IP geolocation and organization data
- **AbuseIPDB**: Malicious IP detection with confidence scores
- **Key Management**: Support for direct API key input or loading from file

### Forensic Capabilities
- **Structured Output**: SIEM-ready format for security tools
- **Partial Results Handling**: Graceful interruption with Ctrl+C
- **Rate Limiting**: Built-in delays to respect API limits
- **Error Handling**: Comprehensive error reporting for troubleshooting

## 🎯 Use Cases

- **Incident Response**: Quickly identify malicious connections during security incidents
- **Malware Analysis**: Monitor network behavior of suspicious processes
- **Log Analysis**: Extract threat intelligence from server logs
- **Security Research**: Identify patterns in network traffic
- **Forensic Investigations**: Create detailed network activity timelines

## 🔒 Security Considerations

- Requires elevated privileges for network monitoring
- API keys should be stored securely (consider using file option for AbuseIPDB key)
- Monitor all processes option generates significant data - use with caution
- Follow organizational policies when analyzing network traffic

## 📊 Output Examples

### Network Monitor Output
```
--------------------------------------------------------------------------------
[2026-03-10 15:42:30] PIDs: 1234, 5678

  TCP    192.168.1.100:54321    203.0.113.5:443    ESTABLISHED     [chrome]
  UDP    192.168.1.100:54322    8.8.8.8:53        CLOSE_WAIT      [chrome]
```

### IP Analyzer Output
```
IP: 203.0.113.5
  Hostname: example.com
  Location: San Francisco, California, US
  Organization: Example ISP Inc.
  Coordinates: 37.7749,-122.4194
  Timezone: America/Los_Angeles
  🚩 Flags: Possible VPN/Proxy/Cloud hosting

  --- AbuseIPDB Report ---
  Abuse Confidence Score: 0% ✅ CLEAN
  Total Reports: 0
  Distinct Reporters: 0
  Usage Type: Data Center/Web Hosting/Transit
  ISP: Example ISP Inc.
  Domain: example.com
```

## 🆘 Troubleshooting

- **Permission Denied**: Run with sudo/administrator privileges
- **Process Not Found**: Verify process name matches exactly
- **API Errors**: Check API keys and rate limits
- **No Output**: Ensure target process has network activity

## 📝 License

This project is open-source. Please refer to the repository for license information.

## 🤝 Contributing

Contributions are welcome! Please submit issues and pull requests to the GitHub repository.

---

**Note**: This tool is intended for legitimate security purposes and authorized testing only. Users are responsible for complying with all applicable laws and regulations.
