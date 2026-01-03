package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: program <logfile.txt> [-o output.txt] [-token YOUR_API_TOKEN]")
		fmt.Println("\nOptional:")
		fmt.Println("  -o output.txt    Save results to file")
		fmt.Println("  -token TOKEN     Use ipinfo.io API token for more requests")
		os.Exit(1)
	}

	logFile := os.Args[1]
	var outputFile string
	var apiToken string

	// Parse arguments
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "-o" && i+1 < len(os.Args) {
			outputFile = os.Args[i+1]
			i++
		} else if os.Args[i] == "-token" && i+1 < len(os.Args) {
			apiToken = os.Args[i+1]
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
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	// Prepare output
	var output strings.Builder
	output.WriteString(fmt.Sprintf("IP Analysis Report - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("Log file: %s\n", logFile))
	output.WriteString(fmt.Sprintf("Total unique public IPs: %d\n", len(ips)))
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Query each IP
	for i, ip := range ips {
		fmt.Printf("[%d/%d] Checking %s...\n", i+1, len(ips), ip)

		info, err := getIPInfo(ip, apiToken)
		if err != nil {
			fmt.Printf("  Error: %v\n\n", err)
			output.WriteString(fmt.Sprintf("IP: %s\n  Error: %v\n\n", ip, err))
			continue
		}

		// Display results
		result := formatIPInfo(info)
		fmt.Print(result)
		output.WriteString(result)

		// Rate limiting - free tier allows 50k requests/month
		// Add small delay to be nice to the API
		if i < len(ips)-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Save to file if specified
	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(output.String()), 0644)
		if err != nil {
			fmt.Printf("Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nResults saved to: %s\n", outputFile)
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
