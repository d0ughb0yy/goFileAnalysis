# goFileAnalysis

A Go program that uses [the filetype module by h2non](https://github.com/h2non/filetype) to analyze given file and check if the file type matches the extension.

The program will also upload the file to VirusTotal and output the results using the official vt-go package.

**Set the VT_API_KEY environment variable inside a .env file.**

**Usage:**

```Shell
cd goFileAnalysis
go build
./goFileAnalysis <file_path>
```
