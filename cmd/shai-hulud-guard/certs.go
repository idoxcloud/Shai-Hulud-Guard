package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// CertificateManager handles OS CA certificate bundles
type CertificateManager interface {
	GetCertBundle() (string, error)
	CreateCertBundle() (string, error)
}

// SystemCertificateManager implements CertificateManager
type SystemCertificateManager struct{}

// GetCertBundle returns the path to the OS CA certificate bundle
func (m *SystemCertificateManager) GetCertBundle() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return m.getMacOSCerts()
	case "linux":
		return m.getLinuxCerts()
	case "windows":
		return m.getWindowsCerts()
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// CreateCertBundle creates a certificate bundle if needed and returns its path
func (m *SystemCertificateManager) CreateCertBundle() (string, error) {
	return m.GetCertBundle()
}

func (m *SystemCertificateManager) getMacOSCerts() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	certPath := filepath.Join(homeDir, ".npm-block-certs.pem")

	// Check if we already have a certificate bundle
	if _, err := os.Stat(certPath); err == nil {
		return certPath, nil
	}

	fmt.Println("  Creating macOS certificate bundle from System Keychain...")

	cmd := exec.Command("security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to extract system certificates: %w", err)
	}

	if err := os.WriteFile(certPath, output, 0600); err != nil {
		return "", fmt.Errorf("failed to write certificate bundle: %w", err)
	}

	fmt.Printf("  ✓ Created certificate bundle: %s\n", certPath)
	return certPath, nil
}

func (m *SystemCertificateManager) getLinuxCerts() (string, error) {
	// Try common Linux CA bundle locations
	certPaths := []string{
		"/etc/ssl/certs/ca-certificates.crt",                      // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",                        // RedHat/CentOS
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",       // RedHat/CentOS (newer)
		"/etc/ca-certificates/extracted/tls-ca-bundle.pem",        // Arch
	}

	for _, path := range certPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no CA certificate bundle found in standard locations")
}

func (m *SystemCertificateManager) getWindowsCerts() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	certPath := filepath.Join(homeDir, ".npm-block-certs.pem")

	// Check if we already have a certificate bundle
	if _, err := os.Stat(certPath); err == nil {
		return certPath, nil
	}

	return "", fmt.Errorf("Windows certificate export not yet implemented\n" +
		"Please export your CA certificates manually:\n" +
		"1. Open certmgr.msc\n" +
		"2. Export Trusted Root Certification Authorities as Base-64 encoded X.509 (.CER)\n" +
		"3. Save to: %s", certPath)
}

// ConfigureNPMCerts configures npm to use the certificate bundle
func ConfigureNPMCerts(certPath string, dryRun bool) error {
	if dryRun {
		fmt.Printf("  [DRY RUN] Would configure npm to use certificates: %s\n", certPath)
		return nil
	}

	cmd := exec.Command("npm", "config", "set", "cafile", certPath, "--location=global")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure npm cafile: %w (output: %s)", err, output)
	}

	fmt.Printf("  ✓ npm configured to use CA bundle: %s\n", certPath)
	return nil
}

// RemoveNPMCerts removes the npm certificate configuration
func RemoveNPMCerts(dryRun bool) error {
	if dryRun {
		fmt.Println("  [DRY RUN] Would remove npm certificate configuration")
		return nil
	}

	cmd := exec.Command("npm", "config", "delete", "cafile", "--location=global")
	_ = cmd.Run() // Ignore errors - key might not exist

	fmt.Println("  ✓ npm certificate configuration removed")
	return nil
}
