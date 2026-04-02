package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/d0ughb0yy/goFileAnalysis/internal/checks"
	"github.com/d0ughb0yy/goFileAnalysis/internal/vtcheck"
)

func main() {
	apiKey := flag.String("api-key", "", "VirusTotal API key (or set VT_API_KEY environment variable)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: ./goFileAnalysis [--api-key KEY] <file_path>")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	userFile := flag.Arg(0)

	apiKeyToUse := *apiKey
	if apiKeyToUse == "" {
		apiKeyToUse = os.Getenv("VT_API_KEY")
	}

	if _, err := os.Stat(userFile); os.IsNotExist(err) {
		fmt.Printf("[!] File does not exist: %s\n", userFile)
		os.Exit(1)
	}

	if apiKeyToUse != "" {
		os.Setenv("VT_API_KEY", apiKeyToUse)
	}

	newFile := checks.File{
		Path:      userFile,
		Name:      filepath.Base(userFile),
		Extension: filepath.Ext(userFile),
	}

	suspicious, err := newFile.CheckHealth()
	if err != nil {
		fmt.Printf("[!] File check failed: %v\n", err)
		os.Exit(1)
	}

	if suspicious {
		if err := vtcheck.VtCheck(userFile); err != nil {
			fmt.Printf("[!] VirusTotal check failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[!] File appears clean, skipping VirusTotal scan, check manually if suspicious")
	}

}
