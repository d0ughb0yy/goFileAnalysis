# goFileAnalysis

A Go program that uses [the filetype module by h2non](https://github.com/h2non/filetype) to analyze given file and check if the file type matches the extension.

The program will also upload the file to VirusTotal and output the results using the official vt-go package.

**Set the VT_API_KEY environment variable and set your API key to be able to upload to VirusTotal.**

**Usage:**

```Shell
export VT_API_KEY=<api_key>
cd goFileAnalysis
go build
./goFileAnalysis <file_path>
```
