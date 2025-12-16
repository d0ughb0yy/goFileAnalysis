package vtCheck

import (
	"fmt"
	"os"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

func VtCheck(filePath string) {

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		fmt.Println("Please set VT_API_KEY environment variable")
		os.Exit(1)
	}

	// Create VirusTotal Client
	client := vt.NewClient(apiKey)

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Send file for scanning
	fmt.Printf("Uploading file: %s\n", filePath)
	scanner := client.NewFileScanner()

	analysis, err := scanner.ScanFile(file, nil)
	if err != nil {
		fmt.Printf("Error uploading file: %v\n", err)
		os.Exit(1)
	}

	analysisID := analysis.ID()
	fmt.Printf("[*] File uploaded. Analysis ID: %s\n", analysisID)
	fmt.Println("[!] Waiting for analysis to complete...")

	// Poll for results
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		time.Sleep(10 * time.Second)

		// Get analysis results
		url := vt.URL("analyses/%s", analysisID)
		analysisObj, err := client.GetObject(url)
		if err != nil {
			fmt.Printf("Error getting results: %s\n", err)
			continue
		}

		status, err := analysisObj.GetString("status")
		if err != nil {
			fmt.Printf("Error getting status: %s\n", err)
			continue
		}

		fmt.Printf("Status: %s\n", status)

		if status == "completed" {
			// Get stats as integers
			malicious, err := analysisObj.GetInt64("stats.malicious")
			if err != nil {
				malicious = 0
			}
			suspicious, err := analysisObj.GetInt64("stats.suspicious")
			if err != nil {
				suspicious = 0
			}
			undetected, err := analysisObj.GetInt64("stats.undetected")
			if err != nil {
				undetected = 0
			}
			harmless, err := analysisObj.GetInt64("stats.harmless")
			if err != nil {
				harmless = 0
			}
			failure, err := analysisObj.GetInt64("stats.failure")
			if err != nil {
				failure = 0
			}
			timeout, err := analysisObj.GetInt64("stats.timeout")
			if err != nil {
				timeout = 0
			}

			fmt.Println("\n=== Scan Results ===")
			fmt.Printf("Malicious: %d\n", malicious)
			fmt.Printf("Suspicious: %d\n", suspicious)
			fmt.Printf("Undetected: %d\n", undetected)
			fmt.Printf("Harmless: %d\n", harmless)
			fmt.Printf("Failure: %d\n", failure)
			fmt.Printf("Timeout: %d\n", timeout)

			if malicious > 0 {
				fmt.Println("[!] File detected as malicious by one or more engines [!]")
			} else {
				fmt.Println("[*] File appears clean [*]")
			}

			return
		}
	}

	fmt.Println("[!] Analysis did not complete within expected time.")
}
