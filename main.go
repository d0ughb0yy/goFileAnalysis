package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/d0ughb0yy/goFileAnalysis/checks"
	"github.com/d0ughb0yy/goFileAnalysis/vtCheck"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./goExtensionCheck <file_path>")
		os.Exit(1)
	}
	userFile := os.Args[1]

	newFile := checks.File{
		Path:      userFile,
		Name:      filepath.Base(userFile),
		Extension: filepath.Ext(userFile),
	}

	needsScan := newFile.CheckHealth()

	if needsScan {
		vtCheck.VtCheck(userFile)
	} else {
		fmt.Println("[!] File appears clean, skipping VirusTotal scan, check manually if suspicious")
	}

}
