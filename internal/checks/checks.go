package checks

import (
	"fmt"
	"os"
	"strings"

	"github.com/h2non/filetype"
)

type File struct {
	Path      string
	Name      string
	Extension string
}

func (f *File) printTypeInfo(fileType, mime string) bool {
	fmt.Printf("[+] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, fileType, mime)
	if f.Extension != "."+fileType {
		fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: .%s\n", f.Path, f.Extension, fileType)
		return true
	}
	return false
}

func (f *File) CheckHealth() (bool, error) {
	file, err := os.Open(f.Path)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", f.Path, err)
	}
	defer file.Close()

	head := make([]byte, 262)
	_, err = file.Read(head)
	if err != nil {
		return false, fmt.Errorf("failed to read file %s: %w", f.Path, err)
	}

	kind, err := filetype.Match(head)
	if err != nil {
		return false, fmt.Errorf("failed to match file type for %s: %w", f.Path, err)
	}

	switch {
	case filetype.IsImage(head),
		filetype.IsVideo(head),
		filetype.IsAudio(head),
		filetype.IsArchive(head),
		filetype.IsDocument(head),
		filetype.IsFont(head),
		filetype.IsApplication(head):
		return f.printTypeInfo(kind.Extension, kind.MIME.Value), nil

	default:
		ext := strings.TrimPrefix(f.Extension, ".")
		if !filetype.IsSupported(ext) {
			fmt.Printf("[!] FILE: %s | UNSUPPORTED TYPE: %s\n", f.Path, f.Extension)
		} else {
			fmt.Printf("[!] FILE: %s | UNKNOWN TYPE: %s\n", f.Path, f.Extension)
		}
		return true, nil
	}

}
