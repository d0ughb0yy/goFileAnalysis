package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/d0ughb0yy/goFileAnalysis/checks"
	"github.com/d0ughb0yy/goFileAnalysis/vtCheck"
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

	if *apiKey != "" {
		os.Setenv("VT_API_KEY", *apiKey)
	}

	if _, err := os.Stat(userFile); os.IsNotExist(err) {
		fmt.Printf("[!] File does not exist: %s\n", userFile)
		os.Exit(1)
	}

	newFile := checks.File{
		Path:      userFile,
		Name:      filepath.Base(userFile),
		Extension: filepath.Ext(userFile),
	}

	needsScan := newFile.CheckHealth()

	if needsScan {
		if err := vtCheck.VtCheck(userFile); err != nil {
			fmt.Printf("[!] VirusTotal check failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[!] File appears clean, skipping VirusTotal scan, check manually if suspicious")
	}

}
