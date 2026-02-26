package vtCheck

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/joho/godotenv"
)

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() || netErr.Temporary() {
			return true
		}
	}

	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"no such host",
		"connection reset",
		"rate limit",
		"too many requests",
		"503",
		"502",
		"504",
	}

	for _, pattern := range retryablePatterns {
		for i := 0; i <= len(errStr)-len(pattern); i++ {
			if i+len(pattern) <= len(errStr) && errStr[i:i+len(pattern)] == pattern {
				return true
			}
		}
	}

	return false
}

func retryWithBackoff(operation func() error, maxRetries int) error {
	var err error
	backoff := time.Duration(2)

	for i := 0; i <= maxRetries; i++ {
		err = operation()
		if err == nil {
			return nil
		}

		if i == maxRetries {
			return fmt.Errorf("failed after %d retries: %v", maxRetries, err)
		}

		if !isRetryableError(err) {
			return fmt.Errorf("non-retryable error: %v", err)
		}

		time.Sleep(backoff * time.Second)
		backoff *= 2
	}

	return err
}

func VtCheck(filePath string) {
	godotenv.Load()

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		fmt.Println("[!] Please set VT_API_KEY environment variable")
		os.Exit(1)
	}
	os.Unsetenv("VT_API_KEY")

	client := vt.NewClient(apiKey)

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[!] Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	fmt.Printf("[*] Uploading file: %s\n", filePath)
	scanner := client.NewFileScanner()

	var analysisObj *vt.Object
	err = retryWithBackoff(func() error {
		var scanErr error
		analysisObj, scanErr = scanner.ScanFile(file, nil)
		return scanErr
	}, 3)

	if err != nil {
		fmt.Printf("[!] Upload failed: %v\n", err)
		os.Exit(1)
	}

	analysisID := analysisObj.ID()
	fmt.Println("[+] File uploaded successfully. Waiting for analysis...")

	maxAttempts := 60
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var sleepDuration time.Duration
		switch {
		case attempt < 10:
			sleepDuration = 15 * time.Second
		case attempt < 30:
			sleepDuration = 30 * time.Second
		default:
			sleepDuration = 60 * time.Second
		}
		time.Sleep(sleepDuration)

		var resultObj *vt.Object
		err = retryWithBackoff(func() error {
			url := vt.URL("analyses/%s", analysisID)
			var getErr error
			resultObj, getErr = client.GetObject(url)
			return getErr
		}, 3)

		if err != nil {
			fmt.Printf("[!] Failed to retrieve analysis results: %v\n", err)
			os.Exit(1)
		}

		status, err := resultObj.GetString("status")
		if err != nil {
			fmt.Printf("[!] Error retrieving analysis status: %v\n", err)
			os.Exit(1)
		}

		if status == "completed" {
			stats := map[string]int64{
				"malicious":  0,
				"suspicious": 0,
				"undetected": 0,
				"harmless":   0,
				"failure":    0,
				"timeout":    0,
			}

			fmt.Println("\n=== Scan Results ===")
			for key := range stats {
				val, err := resultObj.GetInt64(fmt.Sprintf("stats.%s", key))
				if err == nil {
					stats[key] = val
				}
				fmt.Printf("%s: %d\n", key, stats[key])
			}

			results, err := resultObj.Get("results")
			if err == nil {
				resultsMap, ok := results.(map[string]interface{})
				if ok {
					detections := []map[string]string{}

					for engine, data := range resultsMap {
						dataMap, ok := data.(map[string]interface{})
						if !ok {
							continue
						}
						category, _ := dataMap["category"].(string)
						if category == "malicious" || category == "suspicious" {
							result, _ := dataMap["result"].(string)
							detections = append(detections, map[string]string{
								"engine":   engine,
								"category": category,
								"result":   result,
							})
						}
					}

					if len(detections) > 0 {
						fmt.Println("\n=== Detection Details ===")
						fmt.Printf("%-20s | %-12s | %s\n", "Engine", "Category", "Result")
						fmt.Println(strings.Repeat("-", 60))
						for _, d := range detections {
							fmt.Printf("%-20s | %-12s | %s\n", d["engine"], d["category"], d["result"])
						}
					}
				}
			}

			if stats["malicious"] > 0 || stats["suspicious"] > 0 {
				fmt.Printf("\n[!] File detected as malicious/suspicious by one or more engines\n")
			} else {
				fmt.Printf("\n[+] File appears clean\n")
			}

			return
		}
	}

	fmt.Println("[!] Analysis did not complete within the maximum wait time.")
	os.Exit(1)
}
