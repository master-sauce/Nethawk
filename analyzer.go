package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// IPInfo represents the response from ipinfo.io API
type IPInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

// AbuseIPDBResponse represents the response from AbuseIPDB API
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IPVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
	} `json:"data"`
}

func main() {
	// Check if --check flag is used
	if len(os.Args) >= 2 && os.Args[1] == "--check" {
		runIPAnalyzer()
		return
	}

	// Normal network monitoring mode
	runNetworkMonitor()
}

func runIPAnalyzer() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: program --check <logfile.txt> [-o output.txt] [-token YOUR_IPINFO_TOKEN] [-abuseipdb YOUR_ABUSEIPDB_KEY]")
		fmt.Println("\nOptional:")
		fmt.Println("  -o output.txt           Save results to file")
		fmt.Println("  -token TOKEN            Use ipinfo.io API token for more requests")
		fmt.Println("  -abuseipdb KEY          Check IPs against AbuseIPDB (requires API key)")
		fmt.Println("\nPress Ctrl+C to stop analysis and save partial results")
		os.Exit(1)
	}

	logFile := os.Args[2]
	var outputFile string
	var apiToken string
	var abuseIPDBKey string

	// Parse arguments
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "-o" && i+1 < len(os.Args) {
			outputFile = os.Args[i+1]
			i++
		} else if os.Args[i] == "-token" && i+1 < len(os.Args) {
			apiToken = os.Args[i+1]
			i++
		} else if os.Args[i] == "-abuseipdb" && i+1 < len(os.Args) {
			abuseIPDBKey = os.Args[i+1]
			i++
		}
	}

	// Read the log file
	content, err := os.ReadFile(logFile)
	if err != nil {
		fmt.Printf("Error reading log file: %v\n", err)
		os.Exit(1)
	}

	// Extract unique public IPs
	ips := extractPublicIPs(string(content))

	if len(ips) == 0 {
		fmt.Println("No public IP addresses found in log file.")
		os.Exit(0)
	}

	fmt.Printf("Found %d unique public IP addresses\n", len(ips))
	fmt.Println("Press Ctrl+C at any time to stop and save partial results")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()
	
	// Flush stdout to ensure message is displayed
	os.Stdout.Sync()

	// Prepare output
	var output strings.Builder
	output.WriteString(fmt.Sprintf("IP Analysis Report - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("Log file: %s\n", logFile))
	output.WriteString(fmt.Sprintf("Total unique public IPs: %d\n", len(ips)))
	if abuseIPDBKey != "" {
		output.WriteString("AbuseIPDB: Enabled\n")
	}
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Setup signal handler with defer for cleanup
	interrupted := false
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	defer func() {
		if interrupted && outputFile != "" {
			output.WriteString("\n--- ANALYSIS INTERRUPTED ---\n")
			err := os.WriteFile(outputFile, []byte(output.String()), 0644)
			if err != nil {
				fmt.Printf("Error writing output file: %v\n", err)
			} else {
				fmt.Printf("Partial results saved to: %s\n", outputFile)
			}
		}
	}()

	// Handle interrupt in goroutine
	go func() {
		<-sigChan
		fmt.Println("\n\n⚠️  Ctrl+C detected - stopping after current IP check...")
		interrupted = true
	}()

	// Query each IP
	for i, ip := range ips {
		// Check if interrupted before starting next IP
		if interrupted {
			break
		}

		fmt.Printf("[%d/%d] Checking %s...\n", i+1, len(ips), ip)
		os.Stdout.Sync() // Flush output immediately

		// Use a timeout context for API calls
		info, err := getIPInfo(ip, apiToken)
		if interrupted {
			break
		}
		
		if err != nil {
			fmt.Printf("  Error: %v\n\n", err)
			output.WriteString(fmt.Sprintf("IP: %s\n  Error: %v\n\n", ip, err))
			continue
		}

		// Display ipinfo.io results
		result := formatIPInfo(info)
		fmt.Print(result)
		os.Stdout.Sync() // Flush after each IP result
		output.WriteString(result)

		// Check AbuseIPDB if key provided
		if abuseIPDBKey != "" && !interrupted {
			abuseData, err := checkAbuseIPDB(ip, abuseIPDBKey)
			if interrupted {
				break
			}
			if err != nil {
				abuseResult := fmt.Sprintf("  AbuseIPDB Error: %v\n\n", err)
				fmt.Print(abuseResult)
				output.WriteString(abuseResult)
			} else {
				abuseResult := formatAbuseIPDBInfo(abuseData)
				fmt.Print(abuseResult)
				os.Stdout.Sync() // Flush after abuse report
				output.WriteString(abuseResult)
			}
		}

		// Rate limiting - check for interrupt during sleep
		if i < len(ips)-1 && !interrupted {
			for j := 0; j < 5; j++ {
				if interrupted {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	// Save complete results if not interrupted
	if !interrupted && outputFile != "" {
		err := os.WriteFile(outputFile, []byte(output.String()), 0644)
		if err != nil {
			fmt.Printf("Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nResults saved to: %s\n", outputFile)
	}

	if interrupted {
		os.Exit(130)
	}
}

func runNetworkMonitor() {
	if len(os.Args) < 2 {
		fmt.Println("Network Monitor Usage:")
		fmt.Println("  program <process_name> [sleep_seconds] [-o logfile.txt]")
		fmt.Println("\nIP Analyzer Usage:")
		fmt.Println("  program --check <logfile.txt> [-o output.txt] [-token YOUR_IPINFO_TOKEN] [-abuseipdb YOUR_ABUSEIPDB_KEY]")
		os.Exit(1)
	}

	// Check privileges based on OS
	if runtime.GOOS == "windows" && !isAdmin() {
		elevateToAdmin()
		return
	}

	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && os.Geteuid() != 0 {
		fmt.Printf("This program requires root privileges on %s.\n", runtime.GOOS)
		fmt.Println("Please run with: sudo ./program <process_name> [sleep_seconds] [-o logfile.txt]")
		os.Exit(1)
	}

	processName := os.Args[1]
	sleepDuration := 2 * time.Second
	var logFile string

	// Parse arguments
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "-o" && i+1 < len(os.Args) {
			logFile = os.Args[i+1]
			i++ // Skip next arg
		} else {
			if seconds, err := strconv.Atoi(os.Args[i]); err == nil {
				sleepDuration = time.Duration(seconds) * time.Second
			}
		}
	}

	// Open log file if specified
	var logFileHandle *os.File
	var err error
	if logFile != "" {
		logFileHandle, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Error opening log file: %v\n", err)
			os.Exit(1)
		}
		defer logFileHandle.Close()
		fmt.Printf("Logging to: %s\n", logFile)
	}

	for {
		pids := getProcessIDs(processName)

		if len(pids) > 0 {
			clearScreen()

			timestamp := time.Now().Format("2006-01-02 15:04:05")
			separator := strings.Repeat("-", 80)

			output := fmt.Sprintf("\n%s\n[%s] PIDs: %s\n\n", separator, timestamp, strings.Join(pids, ", "))
			fmt.Print(output)

			if logFileHandle != nil {
				logFileHandle.WriteString(output)
			}

			// Filter network connections output
			netOutput := filterNetworkOutput(pids)
			fmt.Print(netOutput)

			if logFileHandle != nil {
				logFileHandle.WriteString(netOutput)
			}

			time.Sleep(sleepDuration)
		} else {
			time.Sleep(sleepDuration)
		}
	}
}

func extractPublicIPs(content string) []string {
	// Regex to match IPv4 addresses
	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	matches := ipRegex.FindAllString(content, -1)

	// Use map to store unique public IPs
	uniqueIPs := make(map[string]bool)

	for _, ip := range matches {
		if isPublicIP(ip) {
			uniqueIPs[ip] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		result = append(result, ip)
	}

	return result
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Filter out special addresses
	if ipStr == "0.0.0.0" || ipStr == "255.255.255.255" {
		return false
	}

	// Check if it's a private IP
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() {
		return false
	}

	// Additional checks for special ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
		"127.0.0.0/8",    // Loopback
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return false
		}
	}

	return true
}

func checkAbuseIPDB(ip string, apiKey string) (*AbuseIPDBResponse, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Key", apiKey)
	req.Header.Add("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var abuseResp AbuseIPDBResponse
	err = json.Unmarshal(body, &abuseResp)
	if err != nil {
		return nil, err
	}

	return &abuseResp, nil
}

func formatAbuseIPDBInfo(abuse *AbuseIPDBResponse) string {
	var sb strings.Builder

	sb.WriteString("  --- AbuseIPDB Report ---\n")
	sb.WriteString(fmt.Sprintf("  Abuse Confidence Score: %d%%", abuse.Data.AbuseConfidenceScore))

	// Color code the severity
	if abuse.Data.AbuseConfidenceScore >= 75 {
		sb.WriteString(" 🔴 HIGH RISK\n")
	} else if abuse.Data.AbuseConfidenceScore >= 25 {
		sb.WriteString(" 🟡 MODERATE RISK\n")
	} else if abuse.Data.AbuseConfidenceScore > 0 {
		sb.WriteString(" 🟢 LOW RISK\n")
	} else {
		sb.WriteString(" ✅ CLEAN\n")
	}

	sb.WriteString(fmt.Sprintf("  Total Reports: %d\n", abuse.Data.TotalReports))
	sb.WriteString(fmt.Sprintf("  Distinct Reporters: %d\n", abuse.Data.NumDistinctUsers))

	if abuse.Data.LastReportedAt != "" {
		sb.WriteString(fmt.Sprintf("  Last Reported: %s\n", abuse.Data.LastReportedAt))
	}

	if abuse.Data.UsageType != "" {
		sb.WriteString(fmt.Sprintf("  Usage Type: %s\n", abuse.Data.UsageType))
	}

	if abuse.Data.ISP != "" {
		sb.WriteString(fmt.Sprintf("  ISP: %s\n", abuse.Data.ISP))
	}

	if abuse.Data.Domain != "" {
		sb.WriteString(fmt.Sprintf("  Domain: %s\n", abuse.Data.Domain))
	}

	if abuse.Data.IsWhitelisted {
		sb.WriteString("  ✅ Whitelisted\n")
	}

	sb.WriteString("\n")

	return sb.String()
}

func getIPInfo(ip string, token string) (*IPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add token if provided
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info IPInfo
	err = json.Unmarshal(body, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func formatIPInfo(info *IPInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("IP: %s\n", info.IP))

	if info.Hostname != "" {
		sb.WriteString(fmt.Sprintf("  Hostname: %s\n", info.Hostname))
	}

	if info.City != "" || info.Region != "" || info.Country != "" {
		location := []string{}
		if info.City != "" {
			location = append(location, info.City)
		}
		if info.Region != "" {
			location = append(location, info.Region)
		}
		if info.Country != "" {
			location = append(location, info.Country)
		}
		sb.WriteString(fmt.Sprintf("  Location: %s\n", strings.Join(location, ", ")))
	}

	if info.Org != "" {
		sb.WriteString(fmt.Sprintf("  Organization: %s\n", info.Org))
	}

	if info.Loc != "" {
		sb.WriteString(fmt.Sprintf("  Coordinates: %s\n", info.Loc))
	}

	if info.Timezone != "" {
		sb.WriteString(fmt.Sprintf("  Timezone: %s\n", info.Timezone))
	}

	// Add threat assessment hints
	sb.WriteString(flagSuspiciousInfo(info))

	sb.WriteString("\n")

	return sb.String()
}

func flagSuspiciousInfo(info *IPInfo) string {
	var flags []string

	// Check for VPN/Proxy/Hosting indicators in org name
	suspiciousOrgs := []string{
		"vpn", "proxy", "hosting", "cloud", "datacenter", "data center",
		"digital ocean", "amazon", "aws", "google cloud", "azure",
		"ovh", "hetzner", "linode", "vultr",
	}

	orgLower := strings.ToLower(info.Org)
	for _, suspicious := range suspiciousOrgs {
		if strings.Contains(orgLower, suspicious) {
			flags = append(flags, "Possible VPN/Proxy/Cloud hosting")
			break
		}
	}

	// Flag certain countries (common for malware C2)
	suspiciousCountries := []string{"RU", "CN", "KP", "IR"}
	for _, country := range suspiciousCountries {
		if info.Country == country {
			flags = append(flags, fmt.Sprintf("⚠️  High-risk country: %s", info.Country))
			break
		}
	}

	if len(flags) > 0 {
		return "  🚩 Flags: " + strings.Join(flags, ", ") + "\n"
	}

	return ""
}

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}

	// Check Windows administrator privileges
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command",
		"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	result := strings.TrimSpace(string(output))
	return result == "True"
}

func elevateToAdmin() {
	// Get the current executable path
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}

	// Prepare arguments
	args := strings.Join(os.Args[1:], " ")

	// Use PowerShell to elevate with UAC prompt
	psCmd := fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList '%s' -Verb RunAs", exe, args)
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psCmd)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to elevate privileges: %v\n", err)
		fmt.Println("This program requires administrator privileges.")
		os.Exit(1)
	}
}

func getProcessIDs(processName string) []string {
	var pids []string

	if runtime.GOOS == "windows" {
		// Use PowerShell Get-Process with ExecutionPolicy Bypass
		psCmd := fmt.Sprintf("(Get-Process -Name '%s' -ErrorAction SilentlyContinue).Id", processName)
		cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psCmd)
		output, err := cmd.Output()
		if err != nil {
			return pids
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				pids = append(pids, line)
			}
		}
	} else {
		// Unix-like systems (Linux, macOS)
		cmd := exec.Command("pgrep", processName)
		output, err := cmd.Output()
		if err != nil {
			return pids
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				pids = append(pids, line)
			}
		}
	}

	return pids
}

func filterNetworkOutput(pids []string) string {
	switch runtime.GOOS {
	case "windows":
		return filterWindowsNetstat(pids)
	case "linux":
		return filterLinuxNetstat(pids)
	case "darwin":
		return filterMacOSLsof(pids)
	default:
		return "Unsupported operating system\n"
	}
}

func filterWindowsNetstat(pids []string) string {
	// Create the regex pattern exactly like the original PowerShell script
	pidList := strings.Join(pids, "|")
	pattern := fmt.Sprintf(" (%s)$|^\\s{4,}", pidList)

	// Use PowerShell Select-String to filter netstat output with the regex pattern
	psCmd := fmt.Sprintf("NETSTAT.EXE -anob | Select-String -Pattern '%s'", pattern)
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psCmd)

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return string(output)
}

func filterLinuxNetstat(pids []string) string {
	// Linux - use netstat -anp
	cmd := exec.Command("netstat", "-anp")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	var filteredLines []string

	// Create regex patterns for matching PIDs
	pidPatterns := make([]*regexp.Regexp, 0)
	for _, pid := range pids {
		// Match PID in format: "12345/programname" or just "12345/-"
		pattern := regexp.MustCompile(fmt.Sprintf(`\b%s(/|$)`, regexp.QuoteMeta(pid)))
		pidPatterns = append(pidPatterns, pattern)
	}

	// Also match lines that start with 4+ spaces (continuation lines)
	indentPattern := regexp.MustCompile(`^\s{4,}`)

	lastMatched := false
	for _, line := range lines {
		matched := false

		// Check if line matches any PID pattern
		for _, pattern := range pidPatterns {
			if pattern.MatchString(line) {
				matched = true
				break
			}
		}

		// Check if it's an indented continuation line following a matched line
		if !matched && lastMatched && indentPattern.MatchString(line) {
			matched = true
		}

		if matched {
			filteredLines = append(filteredLines, line)
		}

		lastMatched = matched
	}

	return strings.Join(filteredLines, "\n") + "\n"
}

func filterMacOSLsof(pids []string) string {
	// macOS - use lsof for network connections
	// lsof -i -n -P shows all internet connections with numeric addresses
	var allOutput strings.Builder

	for _, pid := range pids {
		cmd := exec.Command("lsof", "-i", "-n", "-P", "-p", pid)
		output, err := cmd.Output()
		if err != nil {
			// Process might not have network connections, continue
			continue
		}

		allOutput.WriteString(string(output))
	}

	result := allOutput.String()
	if result == "" {
		return "No network connections found for specified PIDs\n"
	}

	return result
}

func clearScreen() {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}
