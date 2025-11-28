package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
Version  = "1.0.0"
NexusURL = "https://infra.gla.eim.idoxgroup.local/nexus/repository/npm-public"
ReportsDir = "/var/log/shai-hulud" // Directory for storing scan reports
)

func customUsage() {
	fmt.Fprintf(os.Stderr, "Shai-Hulud Guard v%s - Supply Chain Malware Protection\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage: %s [command] [options]\n\n", os.Args[0])
	
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  -install              Install Shai-Hulud protection (blocks npm public registry)\n")
	fmt.Fprintf(os.Stderr, "  -uninstall            Uninstall protection and restore original configuration\n")
	fmt.Fprintf(os.Stderr, "  -status               Check protection status\n")
	fmt.Fprintf(os.Stderr, "  -report               Generate comprehensive system security report (scan + status)\n")
	fmt.Fprintf(os.Stderr, "  -scan                 Scan for Shai-Hulud indicators\n")
	fmt.Fprintf(os.Stderr, "  -scan-s3              Scan S3 bucket for Shai-Hulud indicators\n")
	fmt.Fprintf(os.Stderr, "  -clear-cache          Clear scan cache and checkpoints\n")
	fmt.Fprintf(os.Stderr, "  -version              Show version information\n")
	fmt.Fprintf(os.Stderr, "  -backup-info          Show location of hosts file backup\n")
	
	fmt.Fprintf(os.Stderr, "\nGeneral Options:\n")
	fmt.Fprintf(os.Stderr, "  -yes                  Skip dry-run and apply changes immediately\n")
	
	fmt.Fprintf(os.Stderr, "\nScan Options (use with -scan):\n")
	fmt.Fprintf(os.Stderr, "  -mode string          Scan mode: 'quick' or 'full' (default: quick)\n")
	fmt.Fprintf(os.Stderr, "  -root string          Root directory to scan (default: $HOME)\n")
	fmt.Fprintf(os.Stderr, "  -output string        Output report file path\n")
	fmt.Fprintf(os.Stderr, "  -no-cache             Disable caching\n")
	fmt.Fprintf(os.Stderr, "  -rebuild-cache        Rebuild compromise cache\n")
	fmt.Fprintf(os.Stderr, "  -force-scan           Force scanning even if no node_modules found\n")
	fmt.Fprintf(os.Stderr, "  -verbose              Verbose output\n")
	
	fmt.Fprintf(os.Stderr, "\nS3 Scan Options (use with -scan-s3):\n")
	fmt.Fprintf(os.Stderr, "  -access-key string    S3 access key (required)\n")
	fmt.Fprintf(os.Stderr, "  -secret-key string    S3 secret key (required)\n")
	fmt.Fprintf(os.Stderr, "  -host string          S3 host (required)\n")
	fmt.Fprintf(os.Stderr, "  -bucket string        S3 bucket name (required)\n")
	fmt.Fprintf(os.Stderr, "  -path string          S3 bucket path (required)\n")
	fmt.Fprintf(os.Stderr, "  -protocol string      S3 protocol: 'http' or 'https' (default: https)\n")
	fmt.Fprintf(os.Stderr, "  -port string          S3 port (default: 9000)\n")
	fmt.Fprintf(os.Stderr, "  -verbose              Verbose output\n")
	
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Protection:\n")
	fmt.Fprintf(os.Stderr, "  sudo %s -install                    # Preview then install\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  sudo %s -install -yes               # Install without preview\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  sudo %s -status                     # Check status\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -backup-info                     # Show backup location\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  # Scanning:\n")
	fmt.Fprintf(os.Stderr, "  %s -scan                            # Quick scan of $HOME\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -scan -mode full                 # Full comprehensive scan\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -scan -root /path/to/dir -mode full\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -scan -output report.txt -no-cache\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  # S3 Scanning:\n")
	fmt.Fprintf(os.Stderr, "  %s -scan-s3 -access-key KEY -secret-key SECRET \\\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "    -host s3.example.com -bucket my-bucket -path /data\n")
	fmt.Fprintf(os.Stderr, "  %s -scan-s3 -access-key KEY -secret-key SECRET \\\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "    -host s3.example.com -bucket my-bucket -path /data -verbose\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  # Uninstall:\n")
	fmt.Fprintf(os.Stderr, "  sudo %s -uninstall                  # Preview then remove\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  sudo %s -uninstall -yes             # Remove without preview\n", os.Args[0])
}

func main() {
	var (
		install    = flag.Bool("install", false, "Install Shai-Hulud protection (blocks npm public registry)")
		uninstall  = flag.Bool("uninstall", false, "Uninstall protection and restore original configuration")
		scan       = flag.Bool("scan", false, "Scan for Shai-Hulud indicators (uses embedded scanner script)")
		scanS3     = flag.Bool("scan-s3", false, "Scan S3 bucket for Shai-Hulud indicators (requires mc and jq)")
		status     = flag.Bool("status", false, "Check protection status")
		report     = flag.Bool("report", false, "Generate comprehensive report (scan + status)")
		clearCache = flag.Bool("clear-cache", false, "Clear scan cache and checkpoints")
		version    = flag.Bool("version", false, "Show version")
		confirm    = flag.Bool("yes", false, "Skip dry-run and apply changes immediately (default: false)")
		backupInfo = flag.Bool("backup-info", false, "Show location of hosts file backup")
		
		// Scan-specific flags
		scanMode      = flag.String("mode", "full", "Scan mode: quick or full (use with -scan)")
		scanRoot      = flag.String("root", "", "Root directory to scan (use with -scan, default: $HOME)")
		scanOutput    = flag.String("output", "", "Output report file path (use with -scan)")
		scanNoCache   = flag.Bool("no-cache", false, "Disable caching (use with -scan)")
		scanRebuild   = flag.Bool("rebuild-cache", false, "Rebuild compromise cache (use with -scan)")
		scanForce     = flag.Bool("force-scan", false, "Force scanning even if no node_modules found (use with -scan)")
		
		// S3 scan-specific flags
		s3AccessKey = flag.String("access-key", os.Getenv("S3_ACCESS_KEY"), "S3 access key (use with -scan-s3, or set S3_ACCESS_KEY env var)")
		s3SecretKey = flag.String("secret-key", os.Getenv("S3_SECRET_KEY"), "S3 secret key (use with -scan-s3, or set S3_SECRET_KEY env var)")
		s3Host      = flag.String("host", os.Getenv("S3_HOST"), "S3 host (use with -scan-s3, or set S3_HOST env var)")
		s3Port      = flag.String("port", "9000", "S3 port (use with -scan-s3)")
		s3Protocol  = flag.String("protocol", "https", "S3 protocol: http or https (use with -scan-s3)")
		s3Bucket    = flag.String("bucket", "", "S3 bucket name (use with -scan-s3)")
		s3Path      = flag.String("path", "", "S3 bucket path (use with -scan-s3)")
		s3Verbose   = flag.Bool("verbose", false, "Verbose output (use with -scan-s3)")
	)

	flag.Usage = customUsage
	flag.Parse()

	if *version {
		fmt.Printf("Shai-Hulud Guard v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *backupInfo {
		service := NewProtectionService(false)
		backupPath := service.HostsManager.GetBackupPath()
		fmt.Printf("Hosts file backup location: %s\n", backupPath)
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			fmt.Println("Status: No backup found (protection not installed)")
		} else {
			fmt.Println("Status: Backup exists")
		}
		os.Exit(0)
	}

	// Handle clear-cache command - doesn't require admin privileges
	if *clearCache {
		cacheDir := filepath.Join(os.TempDir(), "shai-hulud-scanner-cache")
		
		// Check if cache directory exists
		if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
			fmt.Println("No cache found.")
			os.Exit(0)
		}
		
		// Remove cache directory
		fmt.Printf("Clearing scan cache: %s\n", cacheDir)
		if err := os.RemoveAll(cacheDir); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to clear cache: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println("✓ Cache cleared successfully")
		fmt.Println("  Next scan will rebuild cache from scratch")
		os.Exit(0)
	}

	// Handle scan command - doesn't require admin privileges
	if *scan {
		// Validate scan mode to prevent path traversal
		if *scanMode != "quick" && *scanMode != "full" {
			fmt.Fprintf(os.Stderr, "ERROR: Invalid scan mode '%s'. Must be 'quick' or 'full'\n", *scanMode)
			os.Exit(1)
		}
		
		// Build arguments from flags
		var scanArgs []string
		
		// Mode
		scanArgs = append(scanArgs, "-m", *scanMode)
		
		// Root directory
		if *scanRoot != "" {
			scanArgs = append(scanArgs, "-r", *scanRoot)
		}
		
		// Output file
		if *scanOutput != "" {
			scanArgs = append(scanArgs, "-o", *scanOutput)
		}
		
		// Flags
		if *scanNoCache {
			scanArgs = append(scanArgs, "-B")
		}
		if *scanRebuild {
			scanArgs = append(scanArgs, "-c")
		}
		if *scanForce {
			scanArgs = append(scanArgs, "-F")
		}
		if *s3Verbose {
			scanArgs = append(scanArgs, "-v")
		}
		
		// Add any remaining positional arguments
		scanArgs = append(scanArgs, flag.Args()...)
		
		if err := runScanner(scanArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle S3 scan command - doesn't require admin privileges
	if *scanS3 {
		// Build arguments from flags
		var scanArgs []string
		
		// Get credentials from flags or environment variables
		accessKey := *s3AccessKey
		if accessKey == "" {
			accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
		}
		
		secretKey := *s3SecretKey
		if secretKey == "" {
			secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		}
		
		// Warn if credentials are passed via command-line
		if *s3AccessKey != "" || *s3SecretKey != "" {
			fmt.Fprintln(os.Stderr, "⚠️  WARNING: Passing credentials via command-line flags is insecure!")
			fmt.Fprintln(os.Stderr, "   Credentials are visible in process list and shell history.")
			fmt.Fprintln(os.Stderr, "   Recommended: Use environment variables instead:")
			fmt.Fprintln(os.Stderr, "     export AWS_ACCESS_KEY_ID=your-key")
			fmt.Fprintln(os.Stderr, "     export AWS_SECRET_ACCESS_KEY=your-secret")
			fmt.Fprintln(os.Stderr, "")
		}
		
		// Required flags
		if accessKey != "" {
			scanArgs = append(scanArgs, "-a", accessKey)
		}
		if secretKey != "" {
			scanArgs = append(scanArgs, "-s", secretKey)
		}
		if *s3Host != "" {
			scanArgs = append(scanArgs, "-h", *s3Host)
		}
		if *s3Bucket != "" {
			scanArgs = append(scanArgs, "-b", *s3Bucket)
		}
		if *s3Path != "" {
			scanArgs = append(scanArgs, "--path", *s3Path)
		}
		
		// Optional flags
		if *s3Protocol != "https" {
			scanArgs = append(scanArgs, "-p", *s3Protocol)
		}
		if *s3Port != "9000" {
			scanArgs = append(scanArgs, "-P", *s3Port)
		}
		if *s3Verbose {
			scanArgs = append(scanArgs, "-v")
		}
		
		// Add any remaining positional arguments
		scanArgs = append(scanArgs, flag.Args()...)
		
		if err := runS3Scanner(scanArgs); err != nil {
			fmt.Fprintf(os.Stderr, "S3 scan failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle report command - generates comprehensive report
	if *report {
		// Validate and sanitize scan mode to prevent path traversal
		reportMode := *scanMode
		if reportMode != "quick" && reportMode != "full" {
			fmt.Fprintf(os.Stderr, "ERROR: Invalid scan mode '%s'. Must be 'quick' or 'full'\n", reportMode)
			os.Exit(1)
		}
		
		// Use full scan mode for reports unless explicitly specified
		if reportMode == "quick" && !isFlagSet("mode") {
			reportMode = "full"
		}
		if err := generateReport(reportMode, *scanRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Report generation failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle status command - doesn't require admin privileges
	if *status {
		service := NewProtectionService(false)
		showStatus(service)
		os.Exit(0)
	}

	// Check for root/admin privileges (except for version, backup-info, scan, report, and status)
	if !isRunningAsAdmin() {
		fmt.Fprintln(os.Stderr, "ERROR: This tool must be run with sudo/administrator privileges")
		fmt.Fprintln(os.Stderr, "Please run: sudo shai-hulud-guard [options]")
		os.Exit(1)
	}

	switch {
	case *install:
		// First pass: dry-run to show what will happen
		if !*confirm {
			dryRunService := NewProtectionService(true)
			if err := dryRunService.Install(); err != nil {
				fmt.Fprintf(os.Stderr, "Preview failed: %v\n", err)
				os.Exit(1)
			}
			
			// Ask for confirmation
			if !promptConfirm("\nApply these changes?") {
				fmt.Println("Operation cancelled.")
				os.Exit(0)
			}
			fmt.Println()
		}
		
		// Second pass: actual installation
		service := NewProtectionService(false)
		if err := service.Install(); err != nil {
			fmt.Fprintf(os.Stderr, "Installation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n✓ Shai-Hulud protection installed successfully")
		fmt.Printf("  npm traffic redirected to: %s\n", NexusURL)

	case *uninstall:
		// First pass: dry-run to show what will happen
		if !*confirm {
			dryRunService := NewProtectionService(true)
			if err := dryRunService.Uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "Preview failed: %v\n", err)
				os.Exit(1)
			}
			
			// Ask for confirmation
			if !promptConfirm("\nApply these changes?") {
				fmt.Println("Operation cancelled.")
				os.Exit(0)
			}
			fmt.Println()
		}
		
		// Second pass: actual uninstallation
		service := NewProtectionService(false)
		if err := service.Uninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "Uninstallation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n✓ Shai-Hulud protection removed")

	default:
		customUsage()
	}
}

func isRunningAsAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		return isWindowsAdmin()
	default:
		return os.Geteuid() == 0
	}
}

func showStatus(service *ProtectionService) {
	fmt.Println("Shai-Hulud Guard Status:")
	fmt.Println("═══════════════════════════")

	blocked, configured, vpnConnected := service.Status()

	printStatus("npm public registry blocked", blocked)
	printStatus("npm configured for Nexus", configured)
	printStatus("VPN connectivity", vpnConnected)

	fmt.Println()
	if blocked && configured {
		fmt.Println("✓ Protection is ACTIVE")
	} else {
		fmt.Println("✗ Protection is NOT active - run with --install")
	}
	
	// Show backup info
	backupPath := service.HostsManager.GetBackupPath()
	if _, err := os.Stat(backupPath); err == nil {
		fmt.Printf("\nBackup location: %s\n", backupPath)
	}
	
	// Check for recent scan reports
	reportDirs := []string{ReportsDir, filepath.Join(os.TempDir(), "shai-hulud-reports")}
	
	var newestReport string
	var newestTime time.Time
	
	for _, reportsDir := range reportDirs {
		if entries, err := os.ReadDir(reportsDir); err == nil && len(entries) > 0 {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				
				// Check if it's a report file
				if strings.HasPrefix(entry.Name(), "shai-hulud-report-") || 
				   strings.HasPrefix(entry.Name(), "ShaiHulud-Scan-Report-") {
					info, err := entry.Info()
					if err == nil && info.ModTime().After(newestTime) {
						newestTime = info.ModTime()
						newestReport = filepath.Join(reportsDir, entry.Name())
					}
				}
			}
		}
	}
	
	if newestReport != "" {
		fmt.Printf("\nRecent scan report:\n")
		fmt.Printf("  Location: %s\n", newestReport)
		fmt.Printf("  Time:     %s\n", newestTime.Format("2006-01-02 15:04:05"))
		
		// Parse and display scan results
		if complete, compromised, maliciousCount, err := parseScanReport(newestReport); err == nil {
			if !complete {
				fmt.Printf("  Status:   ⚠️  SCAN INCOMPLETE (interrupted or failed)\n")
			} else if compromised {
				fmt.Printf("  Status:   🚨 SYSTEM COMPROMISED\n")
				if maliciousCount > 0 {
					fmt.Printf("  Threats:  %d indicator(s) of compromise detected\n", maliciousCount)
				}
			} else {
				fmt.Printf("  Status:   ✓ No threats detected\n")
			}
		}
	}
	
	// Overall security assessment
	fmt.Println()
	fmt.Println("═══════════════════════════")
	fmt.Println("Overall Security Status:")
	fmt.Println("═══════════════════════════")
	
	if newestReport != "" {
		complete, compromised, _, err := parseScanReport(newestReport)
		if err == nil && complete && !compromised && blocked && configured {
			fmt.Println("✓ SYSTEM SECURE")
			fmt.Println("  • Protection is active")
			fmt.Println("  • Recent scan shows no threats")
		} else {
			fmt.Println("⚠️  REVIEW REQUIRED")
			if !blocked || !configured {
				fmt.Println("  • Protection is not fully active")
			}
			if err != nil || !complete {
				fmt.Println("  • No complete scan available")
			} else if compromised {
				fmt.Println("  • Threats detected in scan")
			}
		}
	} else {
		if blocked && configured {
			fmt.Println("⚠️  PROTECTION ACTIVE, NO SCAN")
			fmt.Println("  • Protection is active")
			fmt.Println("  • No scan report available")
			fmt.Println("  • Run 'shai-hulud-guard -report' to verify")
		} else {
			fmt.Println("✗ SYSTEM AT RISK")
			fmt.Println("  • Protection is not active")
			fmt.Println("  • No scan report available")
		}
	}
}

func printStatus(label string, status bool) {
	icon := "✗"
	if status {
		icon = "✓"
	}
	fmt.Printf("  %s %s\n", icon, label)
}

// isFlagSet checks if a command-line flag was explicitly set
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// promptConfirm asks the user for confirmation (default: no)
func promptConfirm(message string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", message)
	
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// parseScanReport extracts key information from a scan report file
func parseScanReport(reportPath string) (complete bool, compromised bool, maliciousCount int, err error) {
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return false, false, 0, err
	}
	
	reportText := string(content)
	
	// Check if scan completed successfully
	if strings.Contains(reportText, "Scan completed in") || 
	   strings.Contains(reportText, "[OK] No indicators of Shai-Hulud compromise") ||
	   strings.Contains(reportText, "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND") {
		complete = true
	}
	
	// Check for compromise indicators
	if strings.Contains(reportText, "[!] CRITICAL:") ||
	   strings.Contains(reportText, "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND") ||
	   strings.Contains(reportText, "Malicious packages detected:") ||
	   strings.Contains(reportText, "Compromised packages found:") {
		compromised = true
	}
	
	// Try to extract malicious package count
	if idx := strings.Index(reportText, "Malicious packages detected:"); idx != -1 {
		line := reportText[idx:]
		if endIdx := strings.Index(line, "\n"); endIdx != -1 {
			line = line[:endIdx]
			fmt.Sscanf(line, "Malicious packages detected: %d", &maliciousCount)
		}
	}
	
	// Try to extract indicator count from summary
	if idx := strings.Index(reportText, "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND:"); idx != -1 {
		line := reportText[idx:]
		if endIdx := strings.Index(line, "\n"); endIdx != -1 {
			line = line[:endIdx]
			var count int
			if n, _ := fmt.Sscanf(line, "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: %d item(s)", &count); n == 1 {
				maliciousCount = count
			}
		}
	}
	
	return complete, compromised, maliciousCount, nil
}

// generateReport creates a comprehensive security report including scan results and guard status
func generateReport(scanMode, scanRoot string) error {
	// Try to use system reports directory, fall back to temp if no permission
	reportsDir := ReportsDir
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		// Fall back to temp directory if we can't write to /var/log/shai-hulud
		reportsDir = filepath.Join(os.TempDir(), "shai-hulud-reports")
		if err := os.MkdirAll(reportsDir, 0755); err != nil {
			return fmt.Errorf("failed to create reports directory: %w", err)
		}
	}
	
	// Generate timestamped report filename
	timestamp := time.Now().Format("20060102-150405")
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("shai-hulud-report-%s-%s.txt", scanMode, timestamp))
	
	// Create report file for writing
	reportFile, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer reportFile.Close()
	
	// Create a multi-writer to write to both console and file
	multiWriter := io.MultiWriter(os.Stdout, reportFile)
	
	// Write header to both console and file
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter, "    Shai-Hulud Security Report")
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter)
	
	if reportsDir != ReportsDir {
		fmt.Fprintln(multiWriter, "Note: Using temporary reports directory")
		fmt.Fprintf(multiWriter, "      Location: %s\n", reportsDir)
		fmt.Fprintln(multiWriter, "      (Run with sudo to use system directory: /var/log/shai-hulud)")
		fmt.Fprintln(multiWriter)
	}
	
	fmt.Fprintf(multiWriter, "Running %s scan...\n", scanMode)
	fmt.Fprintf(multiWriter, "Timestamp: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	// Build scan arguments - use a temp file for scan output first
	tempScanFile := reportPath + ".scan.tmp"
	scanArgs := []string{"-m", scanMode, "-o", tempScanFile}
	if scanRoot != "" {
		scanArgs = append(scanArgs, "-r", scanRoot)
	}
	
	// Run the scanner (output goes to temp file)
	if err := runScanner(scanArgs); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	defer os.Remove(tempScanFile)
	
	// Read scan results from temp file
	scanContent, err := os.ReadFile(tempScanFile)
	if err != nil {
		return fmt.Errorf("failed to read scan results: %w", err)
	}
	
	// Write scan results section to both console and file
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter, "    Scan Results")
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter)
	fmt.Fprint(multiWriter, string(scanContent))
	
	// Write protection status section to both console and file
	fmt.Fprintln(multiWriter)
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter, "    Protection Status")
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintln(multiWriter)
	
	// Show guard status
	service := NewProtectionService(false)
	blocked, configured, vpnConnected := service.Status()
	
	statusIcon := func(status bool) string {
		if status { return "✓" }
		return "✗"
	}
	
	fmt.Fprintf(multiWriter, "  %s npm public registry blocked\n", statusIcon(blocked))
	fmt.Fprintf(multiWriter, "  %s npm configured for Nexus\n", statusIcon(configured))
	fmt.Fprintf(multiWriter, "  %s VPN connectivity\n", statusIcon(vpnConnected))
	
	fmt.Fprintln(multiWriter)
	if blocked && configured {
		fmt.Fprintln(multiWriter, "✓ Protection is ACTIVE")
	} else {
		fmt.Fprintln(multiWriter, "✗ Protection is NOT active")
		if !blocked || !configured {
			fmt.Fprintln(multiWriter, "  Run 'sudo shai-hulud-guard -install' to enable protection")
		}
	}
	
	// Show backup info
	backupPath := service.HostsManager.GetBackupPath()
	if _, err := os.Stat(backupPath); err == nil {
		fmt.Fprintf(multiWriter, "\nBackup location: %s\n", backupPath)
	}
	
	// Footer
	fmt.Fprintln(multiWriter)
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	fmt.Fprintf(multiWriter, "Report saved to: %s\n", reportPath)
	fmt.Fprintln(multiWriter, "═══════════════════════════════════════════")
	
	return nil
}
