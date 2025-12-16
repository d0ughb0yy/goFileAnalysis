# goFileAnalysis

A Go program that uses [the filetype module by h2non](https://github.com/h2non/filetype) to analyze given file and check if the file type matches the extension.
The program will upload the file to VirusTotal and output the results if the API key is set as the VT_API_KEY environment variable.

**Usage:**

```Shell
export VT_API_KEY=<api_key>
cd goFileAnalysis
go build
./goFileAnalysis <file_path>
```
