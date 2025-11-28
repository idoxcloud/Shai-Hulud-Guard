package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SystemNPMManager implements NPMConfigManager for real npm configuration
type SystemNPMManager struct {
	DryRun bool
}

// Configure implements NPMConfigManager.Configure
func (m *SystemNPMManager) Configure() error {
	if m.DryRun {
		fmt.Printf("  [DRY RUN] Would configure npm registry to: %s\n", NexusURL)
		
		// Show certificate configuration attempt
		certMgr := &SystemCertificateManager{}
		certPath, err := certMgr.GetCertBundle()
		if err != nil {
			fmt.Printf("    • Certificate bundle: Not available (%v)\n", err)
			fmt.Println("    • Would show manual certificate setup instructions")
		} else {
			fmt.Printf("    • Certificate bundle: %s\n", certPath)
			fmt.Println("    • Would configure npm cafile setting")
		}
		
		var npmrcPath string
		if runtime.GOOS == "windows" {
			npmrcPath = filepath.Join(os.Getenv("ProgramData"), "npm", "npmrc")
		} else {
			npmrcPath = "/etc/npmrc"
		}
		fmt.Printf("    • Would write configuration to: %s\n", npmrcPath)
		fmt.Println("    • Would set npm global registry config")
		return nil
	}
	return configureNPMRegistry()
}

// Restore implements NPMConfigManager.Restore
func (m *SystemNPMManager) Restore() error {
	if m.DryRun {
		fmt.Println("  [DRY RUN] Would restore npm configuration")
		fmt.Println("    • Would remove npm certificate configuration")
		fmt.Println("    • Would restore registry to public npm registry (https://registry.npmjs.org/)")
		
		var npmrcPath string
		if runtime.GOOS == "windows" {
			npmrcPath = filepath.Join(os.Getenv("ProgramData"), "npm", "npmrc")
		} else {
			npmrcPath = "/etc/npmrc"
		}
		
		content, err := os.ReadFile(npmrcPath)
		if err == nil && strings.Contains(string(content), "Shai-Hulud Guard") {
			fmt.Printf("    • Would remove: %s\n", npmrcPath)
		} else {
			fmt.Printf("    • No system npmrc found at: %s\n", npmrcPath)
		}
		return nil
	}
	return restoreNPMConfig()
}

// IsConfigured implements NPMConfigManager.IsConfigured
func (m *SystemNPMManager) IsConfigured() bool {
	return isNPMConfigured()
}

func configureNPMRegistry() error {
	// Configure certificate bundle first
	certMgr := &SystemCertificateManager{}
	certPath, err := certMgr.GetCertBundle()
	if err != nil {
		fmt.Printf("  ⚠ Warning: Could not configure certificates: %v\n", err)
		fmt.Println("  You may need to configure certificates manually:")
		fmt.Println("  - macOS: security find-certificate -a -p /Library/Keychains/System.keychain > ~/.npm-block-certs.pem")
		fmt.Println("  - Linux: Use system CA bundle (/etc/ssl/certs/ca-certificates.crt or similar)")
		fmt.Printf("  Then run: npm config set cafile <cert-file> --location=global\\n\\n")
	} else {
		if err := ConfigureNPMCerts(certPath, false); err != nil {
			fmt.Printf("  ⚠ Warning: Could not set npm cafile: %v\\n", err)
		}
	}

	cmd := exec.Command("npm", "config", "set", "registry", NexusURL, "--location=global")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm config failed: %w (output: %s)", err, output)
	}

	if err := writeSystemNPMRC(); err != nil {
		return fmt.Errorf("failed to write system .npmrc: %w", err)
	}

	fmt.Printf("  ✓ npm registry set to: %s\\n", NexusURL)
	return nil
}

func writeSystemNPMRC() error {
var npmrcPath string

if runtime.GOOS == "windows" {
npmrcPath = filepath.Join(os.Getenv("ProgramData"), "npm", "npmrc")
} else {
npmrcPath = "/etc/npmrc"
}

dir := filepath.Dir(npmrcPath)
if err := os.MkdirAll(dir, 0755); err != nil {
return err
}

content := fmt.Sprintf(`# Shai-Hulud Guard Configuration
# This file enforces use of internal npm registry only
registry=%s

# Disable public registry fallback
strict-ssl=true

# Added by Shai-Hulud Guard
`, NexusURL)

return os.WriteFile(npmrcPath, []byte(content), 0644)
}

func restoreNPMConfig() error {
	// Remove certificate configuration
	if err := RemoveNPMCerts(false); err != nil {
		fmt.Printf("  ⚠ Warning: Could not remove npm cafile: %v\\n", err)
	} else {
		fmt.Println("  ✓ npm certificate configuration removed")
	}

	// Set registry back to public npm registry at global level
	cmdGlobal := exec.Command("npm", "config", "set", "registry", "https://registry.npmjs.org/", "--location=global")
	if err := cmdGlobal.Run(); err != nil {
		fmt.Printf("  ⚠ Warning: Could not reset global registry to public: %v\\n", err)
	} else {
		fmt.Println("  ✓ npm global registry restored to public registry")
	}

	// Delete user-level registry config (to use global default)
	cmdUser := exec.Command("npm", "config", "delete", "registry", "--location=user")
	if err := cmdUser.Run(); err != nil {
		// This might fail if it doesn't exist, which is fine
		fmt.Println("  ℹ No user-level registry config to remove")
	} else {
		fmt.Println("  ✓ npm user-level registry config removed")
	}

	var npmrcPath string
	if runtime.GOOS == "windows" {
		npmrcPath = filepath.Join(os.Getenv("ProgramData"), "npm", "npmrc")
	} else {
		npmrcPath = "/etc/npmrc"
	}

	content, err := os.ReadFile(npmrcPath)
	if err == nil && strings.Contains(string(content), "Shai-Hulud Guard") {
		os.Remove(npmrcPath)
		fmt.Printf("  ✓ Removed system npmrc: %s\\n", npmrcPath)
	}

	return nil
}

func isNPMConfigured() bool {
cmd := exec.Command("npm", "config", "get", "registry")
output, err := cmd.Output()
if err != nil {
return false
}

registry := strings.TrimSpace(string(output))
return strings.Contains(registry, "infra.gla.eim.idoxgroup.local")
}
