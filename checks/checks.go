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

func (f *File) CheckHealth() {
	file, err := os.Open(f.Path)
	if err != nil {
		fmt.Println("[!] Error opening file:", err)
	}
	head := make([]byte, 261)
	file.Read(head)

	kind, err := filetype.MatchFile(f.Path)
	if err != nil {
		fmt.Println("Error:", err)
	}

	switch true {
	case filetype.IsImage(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: .%s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsVideo(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: .%s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsAudio(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: .%s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsArchive(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: %s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsDocument(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: %s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsFont(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: %s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	case filetype.IsApplication(head):
		fmt.Printf("[!] FILE NAME: %s | FILE TYPE: %s | MIME: %s\n", f.Path, kind.Extension, kind.MIME.Value)
		if f.Extension != "."+kind.Extension {
			fmt.Printf("[!] SUSPICIOUS FILE: %s | EXTENSION DOES NOT MATCH TYPE | EXTENSION: %s TYPE: %s\n", f.Path, f.Extension, kind.Extension)
		}
		return

	default:
		if !filetype.IsSupported(f.Extension) {
			fmt.Printf("[!] FILE: %s | UNSUPPORTED TYPE: %s", f.Path, f.Extension)
		} else {
			fmt.Printf("[!] FILE: %s | UNKNOWN TYPE: %s", f.Path, f.Extension)
		}
	}

}
