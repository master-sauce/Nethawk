🔍 Introducing NetHawk: A Dual-Purpose Threat Hunting Tool

Nethawk is an open-source security tool for real-time network monitoring and IP intelligence gathering.

installation:

# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/master-sauce/Nethawk/main/install.sh | bash

# Windows
irm https://raw.githubusercontent.com/master-sauce/Nethawk/main/install.ps1 | iex


run the commnads again to Uninstall.


# build from source:

to build it yourself download go, cd to the dir with Nethawk.go and run in terminal: go build Nethawk.go 

do ./Nethawk to display usage.

(sudo or admin are needed to run this this program)


# What Makes NetHawk Different:
🪶 Single Executable - No installation, dependencies, or configuration. Download and run on Windows, Linux, or macOS.
📅 Timestamped Logging - Every connection capture includes timestamps, critical for forensic timelines.
🧠 Intelligent Filtering - Automatically identifies all PIDs for target processes by name, checks for any PID that has connections made and filters TCP/UDP connections with full port visibility
🎯 Universal Log Parser - Regex-based extraction works with ANY log format (Apache, Nginx, firewalls). Automatically deduplicates and focuses on unique public IPs only.
🌐 Built-in Threat Intelligence - Integrated ipinfo.io and AbuseIPDB with visual risk scoring (🔴 HIGH 🟡 MODERATE ✅ CLEAN)
🔐 AbuseIPDB Integration - Load API keys from file for convenience OR pass as flags.

Core Features:
✅ Monitor specific processes or all running processes (Windows/Linux/macOS) ✅ Extract and analyze IPs from any log format ✅ Automated flagging for VPNs, proxies, cloud hosting, high-risk countries ✅ Forensics-ready structured output for SIEM integration ✅ Perfect for USB forensic toolkits and incident response
Built for:
Incident response and forensic investigations
Malware behavior analysis
Log file threat assessment
Security research and threat hunting
Written in Go for minimal resource usage and cross-platform compatibility.

