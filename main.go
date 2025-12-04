package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)


func main() {
	var cfg = Config{}
	flag.StringVar(&cfg.Realm, "realm", "", "realm (e.g. EXAMPLE.COM)")
	flag.StringVar(&cfg.SPN, "spn", "", "SPN (e.g. HTTP/test.example.com)")
	flag.StringVar(&cfg.Keytab, "keytab", "", "keytab file (e.g. test.keytab)")
	flag.StringVar(&cfg.Krb5Config, "krb5config", "", "path to krb5.conf")
	flag.BoolVar(&cfg.UseCC, "usecc", true, "use credential cache (default: false)")
	flag.BoolVar(&cfg.ListCreds, "list", false, "list credentials from cache")
	flag.StringVar(&cfg.CacheName, "cache", "", "credential cache name (default: system default)")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable debug output")
	flag.Parse()

	// Set debug mode globally
	SetDebugMode(cfg.Debug)

	if cfg.ListCreds {
		if err := listCredentials(cfg.CacheName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("=> configuration: %v\n", cfg)
}

// listCredentials retrieves and displays credentials from the credential cache
func listCredentials(cacheName string) error {
	// Create platform-specific credential cache client
	cc, err := NewCCache()
	if err != nil {
		return fmt.Errorf("failed to open credential cache: %w\n\nThis may indicate that the Kerberos credential cache service is not running\nor that you are not logged into a Kerberos realm.", err)
	}
	defer cc.Close()

	// Get default cache name if not specified
	if cacheName == "" {
		cacheName, err = cc.GetDefaultCacheName()
		if err != nil {
			if err == ErrCacheNotFound || err == ErrCredNotFound {
				return fmt.Errorf("no Kerberos credentials found.\n\nYou may need to authenticate first using 'kinit' or log into a Kerberos-enabled domain.")
			}
			// Check for common "no Kerberos" scenarios
			errStr := err.Error()
			if strings.Contains(errStr, "no response") || strings.Contains(errStr, "not configured") {
				return fmt.Errorf("no Kerberos credentials available.\n\nKerberos does not appear to be configured on this system.\nOn macOS, this typically requires joining an Active Directory domain or running 'kinit'.")
			}
			return fmt.Errorf("failed to get default cache name: %w", err)
		}
	}

	fmt.Printf("Credential cache: %s\n", cacheName)

	// Open the cache
	cache, err := cc.OpenCache(cacheName)
	if err != nil {
		if err == ErrCacheNotFound {
			return fmt.Errorf("credential cache not found: %s\n\nThe specified cache does not exist or has been destroyed.", cacheName)
		}
		return fmt.Errorf("failed to open cache: %w", err)
	}
	defer cache.Close()

	// Get the principal
	princ, realm, err := cache.GetPrincipal()
	if err != nil {
		if err == ErrCacheNotFound || err == ErrCredNotFound {
			return fmt.Errorf("no Kerberos credentials found in cache.\n\nYou may need to authenticate first using 'kinit' or log into a Kerberos-enabled domain.")
		}
		return fmt.Errorf("failed to get principal: %w", err)
	}

	fmt.Printf("Default principal: %s@%s\n\n", princ.PrincipalNameString(), realm)

	// Get all credentials
	creds, err := cache.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}

	if len(creds) == 0 {
		fmt.Println("No credentials found.")
		return nil
	}

	// Display credentials
	for i, cred := range creds {
		fmt.Printf("--- Credential %d ---\n", i+1)
		fmt.Printf("  Server:     %s@%s\n", cred.Server.PrincipalNameString(), cred.ServerRealm)
		fmt.Printf("  Client:     %s@%s\n", cred.Client.PrincipalNameString(), cred.ClientRealm)
		fmt.Printf("  Auth time:  %s\n", cred.AuthTime.Format(time.RFC3339))
		fmt.Printf("  Start time: %s\n", cred.StartTime.Format(time.RFC3339))
		fmt.Printf("  End time:   %s\n", cred.EndTime.Format(time.RFC3339))
		fmt.Printf("  Renew till: %s\n", cred.RenewTill.Format(time.RFC3339))

		// Show status
		if cred.IsExpired() {
			fmt.Printf("  Status:     EXPIRED\n")
		} else if cred.IsValid() {
			remaining := cred.TimeRemaining()
			fmt.Printf("  Status:     Valid (expires in %s)\n", formatDuration(remaining))
		} else {
			fmt.Printf("  Status:     Not yet valid\n")
		}

		fmt.Printf("  Key type:   %d\n", cred.Key.KeyType)
		fmt.Println()
	}

	fmt.Printf("Total: %d credential(s)\n", len(creds))
	return nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 24 {
		days := hours / 24
		hours = hours % 24
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}

	return fmt.Sprintf("%dm", minutes)
}
