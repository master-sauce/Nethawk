package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
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
	// Use a subcommand structure
	if len(os.Args) > 1 && os.Args[1] == "chk" {
		// 'chk' subcommand
		checkCmd := flag.NewFlagSet("chk", flag.ExitOnError)
		logFile := checkCmd.String("logfile", "", "Log file to analyze (required).")
		checkCmd.StringVar(logFile, "f", "", "Log file to analyze (required). (shorthand)")
		outputFile := checkCmd.String("output", "", "File to save output to.")
		checkCmd.StringVar(outputFile, "o", "", "File to save output to. (shorthand)")
		ipInfoToken := checkCmd.String("token", "", "API token for ipinfo.io.")
		checkCmd.StringVar(ipInfoToken, "t", "", "API token for ipinfo.io. (shorthand)")
		abuseIPDBKey := checkCmd.String("abuseipdb", "", "API key for AbuseIPDB or path to file containing the key.")
		checkCmd.StringVar(abuseIPDBKey, "a", "", "API key for AbuseIPDB or path to file containing the key. (shorthand)")
		checkCmd.Parse(os.Args[2:])

		// --- NEW: Check if abuseIPDBKey is a file path ---	
		finalAbuseKey := *abuseIPDBKey
		if _, err := os.Stat(*abuseIPDBKey); err == nil {
			// It is a file, read the first line
			file, err := os.Open(*abuseIPDBKey)
			if err != nil {
				fmt.Printf("Error opening keyfile: %v\n", err)
				os.Exit(1)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			if scanner.Scan() {
				finalAbuseKey = scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading keyfile: %v\n", err)
				os.Exit(1)
			}
}

		if *logFile == "" {
			fmt.Println("Error: --logfile is required.")
			checkCmd.PrintDefaults()
			os.Exit(1)
		}
		// In main(), inside the 'chk' block:
		runIPAnalyzer(*logFile, *outputFile, *ipInfoToken, finalAbuseKey)

		} else if len(os.Args) > 1 && os.Args[1] == "mon" {
    // 'mon' subcommand
    monitorCmd := flag.NewFlagSet("mon", flag.ExitOnError)
    processName := monitorCmd.String("process", "", "Process name to monitor.")
    monitorCmd.StringVar(processName, "p", "", "Process name to monitor. (shorthand)")
    
    // --- NEW: Add a boolean flag for -all and --all ---
    monitorAll := monitorCmd.Bool("all", false, "Monitor all running processes.")

    outputFile := monitorCmd.String("output", "", "File to save output to.")
    monitorCmd.StringVar(outputFile, "o", "", "File to save output to. (shorthand)")
    sleepSeconds := monitorCmd.Int("sleep", 2, "Seconds to wait between updates.")
    monitorCmd.IntVar(sleepSeconds, "s", 2, "Seconds to wait between updates. (shorthand)")
    monitorCmd.Parse(os.Args[2:])

    // --- NEW: Validation for mutually exclusive flags ---
    if *processName != "" && *monitorAll {
        fmt.Println("Error: You cannot specify both --process and --all flags.")
        monitorCmd.PrintDefaults()
        os.Exit(1)
    }
    if *processName == "" && !*monitorAll {
        fmt.Println("Error: You must specify either --process or --all.")
        monitorCmd.PrintDefaults()
        os.Exit(1)
    }

    runNetworkMonitor(*processName, *monitorAll, *outputFile, time.Duration(*sleepSeconds)*time.Second)

	} else {
		// Default case: print usage
		fmt.Println("This tool has two modes of operation. Use a subcommand to select one.")
		fmt.Println("\nUsage:")
		fmt.Println("  program mon [flags]")
		fmt.Println("  program chk [flags]")
		
		fmt.Println("\nNetwork Monitor Mode (monitors a running process):")
		fmt.Println(" monitor")
		fmt.Println(" --process, -p <name> (Required) Process name to monitor, or '--all'/'-all' for all processes. (Warning!!!!, a lot of data)")
		fmt.Println(" --output, -o <path> Log network activity to file.")
		fmt.Println(" --sleep, -s <seconds> Seconds between updates (default: 2).")
		fmt.Println("\nExample:")
		fmt.Println("  ./program mon -p chrome -o net.log")
		fmt.Println("  ./program mon --all -s 5")
				
		fmt.Println("\nIP Analyzer Mode (checks IPs in a log file):")
		fmt.Println("  check")
		fmt.Println("    --logfile, -f <path> (Required) Log file to analyze.")
		fmt.Println("    --output, -o <path>    Save results to file.")
		fmt.Println("    --token, -t <string>   ipinfo.io API token.")
		fmt.Println("    --abuseipdb, -a <string> AbuseIPDB API key.")
		
		fmt.Println("\nExample:")
		fmt.Println("  ./program chk -f access.log -o report.txt")
		os.Exit(1)
	}
}


func runIPAnalyzer(logFile, outputFile, apiToken, abuseIPDBKey string) {
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

	// Setup signal handling
	interrupted := false
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n⚠️ Ctrl+C detected - stopping after current IP analysis...")
		interrupted = true
	}()

	// Display initial info
	fmt.Printf("Found %d unique public IP addresses\n", len(ips))
	if outputFile != "" {
		fmt.Printf("Results will be saved to: %s\n", outputFile)
	}
	fmt.Println("Press Ctrl+C at any time to stop and save partial results")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	// Prepare output
	var output strings.Builder
	output.WriteString(fmt.Sprintf("IP Analysis Report - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("Log file: %s\n", logFile))
	output.WriteString(fmt.Sprintf("Total unique public IPs: %d\n", len(ips)))
	if abuseIPDBKey != "" {
		output.WriteString("AbuseIPDB: Enabled\n")
	}
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Query each IP
	for i, ip := range ips {
		// Single interrupt check per loop iteration
		if interrupted {
			break
		}

		fmt.Printf("[%d/%d] Checking %s...\n", i+1, len(ips), ip)
		os.Stdout.Sync()

		// Query ipinfo.io
		info, err := getIPInfo(ip, apiToken)
		if err != nil {
			errMsg := fmt.Sprintf("IP: %s\n  ipinfo.io Error: %v\n\n", ip, err)
			fmt.Print(errMsg)
			output.WriteString(errMsg)
			
			// Rate limit even on error
			if i < len(ips)-1 {
				time.Sleep(500 * time.Millisecond)
			}
			continue
		}

		// Format and display ipinfo results
		result := formatIPInfo(info)
		fmt.Print(result)
		os.Stdout.Sync()
		output.WriteString(result)

		// Query AbuseIPDB if enabled
		if abuseIPDBKey != "" {
			abuseData, err := checkAbuseIPDB(ip, abuseIPDBKey)
			if err != nil {
				abuseResult := fmt.Sprintf("  AbuseIPDB Error: %v\n\n", err)
				fmt.Print(abuseResult)
				output.WriteString(abuseResult)
			} else {
				abuseResult := formatAbuseIPDBInfo(abuseData)
				fmt.Print(abuseResult)
				os.Stdout.Sync()
				output.WriteString(abuseResult)
			}
		}

		// Rate limiting between IPs
		if i < len(ips)-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Save results (partial or complete)
	if outputFile != "" {
		if interrupted {
			output.WriteString("\n--- ANALYSIS INTERRUPTED ---\n")
		}
		err := os.WriteFile(outputFile, []byte(output.String()), 0644)
		if err != nil {
			fmt.Printf("Error writing output file: %v\n", err)
			os.Exit(1)
		}
		if interrupted {
			fmt.Printf("\nPartial results saved to: %s\n", outputFile)
		} else {
			fmt.Printf("\nResults saved to: %s\n", outputFile)
		}
	}

	if interrupted {
		os.Exit(130)
	}
}


func runNetworkMonitor(processName string, monitorAll bool, outputFile string, sleepDuration time.Duration) {
	// ... (privilege and log file checks remain the same) ...
	if runtime.GOOS == "windows" && !isAdmin() {
		elevateToAdmin()
		return
	}
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && os.Geteuid() != 0 {
		fmt.Printf("This program requires root privileges on %s.\n", runtime.GOOS)
		fmt.Println("Please run with: sudo ./program monitor --process <process_name>")
		os.Exit(1)
	}

	var logFileHandle *os.File
	var err error
	if outputFile != "" {
		logFileHandle, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Error opening log file: %v\n", err)
			os.Exit(1)
		}
		defer logFileHandle.Close()
		fmt.Printf("Logging to: %s\n", outputFile)
	}

	for {
		
		var targetName string
		if monitorAll {
			targetName = "-all"
		} else {
			targetName = processName
		}

		pids := getProcessIDs(targetName)

		if len(pids) > 0 {
			// --- The Change is Here ---
			// We will run the slow network command in a background goroutine.

			// A channel to receive the result from the goroutine
			resultChan := make(chan string, 1) // Buffered channel of size 1

			// Start the work in the background
			go func() {
				resultChan <- filterNetworkOutput(pids)
			}()

			// Now, we wait for our sleep duration
			time.Sleep(sleepDuration)

			// After sleeping, clear the screen and print the timestamp
			clearScreen()
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			separator := strings.Repeat("-", 80)
			header := fmt.Sprintf("\n%s\n[%s] PIDs: %s\n\n", separator, timestamp, strings.Join(pids, ", "))
			
			fmt.Print(header)
			if logFileHandle != nil {
				logFileHandle.WriteString(header)
			}

			// Now, we wait for the network data to be ready.
			// If the goroutine finished while we were sleeping, we get the result immediately.
			// If it's still running, we wait here until it's done.
			netOutput := <-resultChan

			fmt.Print(netOutput)
			if logFileHandle != nil {
				logFileHandle.WriteString(netOutput)
			}
		} else {
			// If process not found, just sleep
			time.Sleep(sleepDuration)
		}
	}
}





// --- Helper functions (unchanged from previous versions) ---

func extractPublicIPs(content string) []string {
	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	matches := ipRegex.FindAllString(content, -1)

	uniqueIPs := make(map[string]bool)
	for _, ip := range matches {
		if isPublicIP(ip) {
			uniqueIPs[ip] = true
		}
	}

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

	if ipStr == "0.0.0.0" || ipStr == "255.255.255.255" {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
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

	sb.WriteString(flagSuspiciousInfo(info))
	sb.WriteString("\n")

	return sb.String()
}

func flagSuspiciousInfo(info *IPInfo) string {
	var flags []string

	suspiciousOrgs := []string{"vpn", "proxy", "hosting", "cloud", "datacenter", "data center", "digital ocean", "amazon", "aws", "google cloud", "azure", "ovh", "hetzner", "linode", "vultr"}
	orgLower := strings.ToLower(info.Org)
	for _, suspicious := range suspiciousOrgs {
		if strings.Contains(orgLower, suspicious) {
			flags = append(flags, "Possible VPN/Proxy/Cloud hosting")
			break
		}
	}

	suspiciousCountries := []string{"RU", "CN", "KP", "IR"}
	for _, country := range suspiciousCountries {
		if info.Country == country {
			flags = append(flags, fmt.Sprintf("⚠️ High-risk country: %s", info.Country))
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

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	result := strings.TrimSpace(string(output))
	return result == "True"
}

func elevateToAdmin() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}

	args := strings.Join(os.Args[1:], " ")
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

	// --- NEW: Handle the "-all" case ---
	if processName == "-all" {
		if runtime.GOOS == "windows" {
			// On Windows, Get-Process with no name returns all processes
			psCmd := "(Get-Process -ErrorAction SilentlyContinue).Id"
			cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psCmd)
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						pids = append(pids, line)
					}
				}
			}
		} else {
			// On Linux/macOS, we can list all PIDs. A simple way is to use ps.
			// We use ps -e to list all processes and -o pid to only show the PID column.
			cmd := exec.Command("ps", "-e", "-o", "pid=")
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						pids = append(pids, line)
					}
				}
			}
		}
		return pids // Return the list of all PIDs
	}

	// --- ORIGINAL: Handle the specific process name case ---
	if runtime.GOOS == "windows" {
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
	pidList := strings.Join(pids, "|")
	pattern := fmt.Sprintf(" (%s)$|^^\\s{4,}", pidList)
	psCmd := fmt.Sprintf("NETSTAT.EXE -anob | Select-String -Pattern '%s'", pattern)

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return string(output)
}

func filterLinuxNetstat(pids []string) string {
	cmd := exec.Command("netstat", "-anp")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	var filteredLines []string

	pidPatterns := make([]*regexp.Regexp, 0)
	for _, pid := range pids {
		pattern := regexp.MustCompile(fmt.Sprintf(`\b%s(/|$)`, regexp.QuoteMeta(pid)))
		pidPatterns = append(pidPatterns, pattern)
	}

	indentPattern := regexp.MustCompile(`^^\s{4,}`)
	lastMatched := false

	for _, line := range lines {
		matched := false
		for _, pattern := range pidPatterns {
			if pattern.MatchString(line) {
				matched = true
				break
			}
		}

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
	var allOutput strings.Builder

	for _, pid := range pids {
		cmd := exec.Command("lsof", "-i", "-n", "-P", "-p", pid)
		output, err := cmd.Output()
		if err != nil {
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
