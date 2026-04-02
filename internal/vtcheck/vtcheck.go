package vtcheck

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

const (
	maxPollAttempts = 60
	pollPhase1Limit = 20
	pollPhase2Limit = 60
	pollInterval1   = 15 * time.Second
	pollInterval2   = 30 * time.Second
)

var (
	ErrNoAPIKey     = errors.New("VT_API_KEY environment variable not set")
	ErrFileOpen     = errors.New("failed to open file")
	ErrUploadFailed = errors.New("file upload failed")
	ErrResultsFetch = errors.New("failed to retrieve analysis results")
	ErrStatusFetch  = errors.New("failed to retrieve analysis status")
	ErrTimeout      = errors.New("analysis did not complete within max wait time")
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

func VtCheck(filePath string) error {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		fmt.Println("[!] Please set VT_API_KEY environment variable")
		return ErrNoAPIKey
	}
	if len(apiKey) < 32 {
		fmt.Println("[!] Invalid API key: key appears too short")
		return fmt.Errorf("invalid API key: minimum 32 characters required")
	}

	client := vt.NewClient(apiKey)

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[!] Error opening file: %v\n", err)
		return fmt.Errorf("%w: %v", ErrFileOpen, err)
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
		return fmt.Errorf("%w: %v", ErrUploadFailed, err)
	}

	analysisID := analysisObj.ID()
	fmt.Println("[+] File uploaded successfully. Waiting for analysis...")

	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		var sleepDuration time.Duration
		if attempt < pollPhase1Limit {
			sleepDuration = pollInterval1
		} else if attempt < pollPhase2Limit {
			sleepDuration = pollInterval2
		} else {
			sleepDuration = pollInterval2
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
			return fmt.Errorf("%w: %v", ErrResultsFetch, err)
		}

		status, err := resultObj.GetString("status")
		if err != nil {
			fmt.Printf("[!] Error retrieving analysis status: %v\n", err)
			return fmt.Errorf("%w: %v", ErrStatusFetch, err)
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

			return nil
		}
	}

	fmt.Println("[!] Analysis did not complete within the maximum wait time.")
	return ErrTimeout
}
