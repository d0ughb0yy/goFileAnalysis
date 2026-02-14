package checks

import (
	"fmt"
	"os"

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

func (f *File) CheckHealth() bool {
	file, err := os.Open(f.Path)
	if err != nil {
		fmt.Printf("[!] Error opening file: %v\n", err)
		return false
	}
	defer file.Close()

	head := make([]byte, 261)
	_, err = file.Read(head)
	if err != nil {
		fmt.Printf("[!] Error reading file: %v\n", err)
		return false
	}

	kind, err := filetype.MatchFile(f.Path)
	if err != nil {
		fmt.Printf("[!] Error matching file type: %v\n", err)
		return false
	}

	switch {
	case filetype.IsImage(head),
		filetype.IsVideo(head),
		filetype.IsAudio(head),
		filetype.IsArchive(head),
		filetype.IsDocument(head),
		filetype.IsFont(head),
		filetype.IsApplication(head):
		return f.printTypeInfo(kind.Extension, kind.MIME.Value)

	default:
		if !filetype.IsSupported(f.Extension) {
			fmt.Printf("[!] FILE: %s | UNSUPPORTED TYPE: %s\n", f.Path, f.Extension)
		} else {
			fmt.Printf("[!] FILE: %s | UNKNOWN TYPE: %s\n", f.Path, f.Extension)
		}
		return true
	}

}
