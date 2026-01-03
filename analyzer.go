package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func main() {


	// check args
		if len(os.Args) < 2 {
		fmt.Println("Usage: program <process_name> [sleep_seconds] [-o logfile.txt]")
		os.Exit(1)
	}


	// Check if running as administrator on Windows
	if runtime.GOOS == "windows" && !isAdmin() {
		elevateToAdmin()
		return
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

			// Use PowerShell to filter netstat output with regex
			netstatOutput := filterNetstatOutput(pids)
			fmt.Print(netstatOutput)
			
			if logFileHandle != nil {
				logFileHandle.WriteString(netstatOutput)
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

	// Try to open a privileged registry key
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

func filterNetstatOutput(pids []string) string {
	if runtime.GOOS == "windows" {
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
	} else {
		// Unix-like systems - simple grep approach
		cmd := exec.Command("sh", "-c", fmt.Sprintf("netstat -anp | grep -E '(%s)'", strings.Join(pids, "|")))
		output, err := cmd.Output()
		if err != nil {
			return ""
		}

		return string(output)
	}
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
