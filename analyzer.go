package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func main() {

	//check args
	if len(os.Args) < 2 {
		fmt.Println("Usage: program <process_name> [sleep_seconds] [-o logfile.txt]")
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
