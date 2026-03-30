# goFileAnalysis - Agent Documentation

## Project Overview

A Go file analysis tool that:
1. Analyzes file type vs extension mismatch using the `filetype` library
2. Uploads suspicious files to VirusTotal for scanning
3. Displays scan results including engine detections

## Project Structure

```
goFileAnalysis/
├── main.go              # Entry point
├── checks/
│   └── checks.go        # File health/type checking logic
├── vtCheck/
│   └── vtCheck.go       # VirusTotal API integration
├── .env                 # Environment variables (API keys)
├── go.mod / go.sum      # Go dependencies
├── AGENTS.md            # This file
└── CHANGES.md           # Changelog
```

## Key Files

### main.go
- Entry point
- Takes file path as CLI argument
- Calls `checks.File.CheckHealth()` to determine if file needs scanning
- If suspicious, calls `vtCheck.VtCheck(filePath)`

### checks/checks.go
- `File` struct with Path, Name, Extension fields
- `CheckHealth()` method - returns `true` if file is suspicious and needs VT scan

### vtCheck/vtCheck.go
- `VtCheck(filePath string)` - main function
- Loads `.env` for API key via `godotenv.Load()`
- Uploads file to VirusTotal
- Polls for analysis completion
- Displays: stats summary, detection details table, GUI link

## Dependencies

- `github.com/h2non/filetype` - file type detection
- `github.com/VirusTotal/vt-go` - VT API client
- `github.com/joho/godotenv` - .env file loading

## Running the Tool

```bash
# Set API key (can use .env file)
go run main.go <file_path>

# Or with environment variable
VT_API_KEY=your_key go run main.go <file_path>
```

## Important Notes for Agents

- VT_API_KEY is stored in `.env` - load it using `godotenv.Load()`
- The VT API returns analysis results with a `results` map containing engine detections
- Filter detections by checking `category == "malicious"` or `category == "suspicious"`
- GUI link format: `https://www.virustotal.com/gui/analysis/{analysis_id}` (analysis ID is available from scan response)
- Always test with actual VT API key - mock testing won't work for API-dependent features

## Adding New Features

1. File analysis logic → add to `checks/checks.go`
2. VT integration → add to `vtCheck/vtCheck.go`
3. New dependencies → run `go get` and/or `go mod tidy` and ensure go.mod is updated
4. Test with real files provided by the user and VT API