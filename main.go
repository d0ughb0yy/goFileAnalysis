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

	newFile.CheckHealth()
	vtCheck.VtCheck(userFile)

}
