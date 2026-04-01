# goFileAnalysis

A Go CLI tool that detects file type mismatches and scans suspicious files using VirusTotal.

## Features

- Detects file type vs extension mismatches using magic bytes
- Automatically uploads suspicious files to VirusTotal
- Built-in retry logic with exponential backoff

## Usage

```bash
./goFileAnalysis <file_path>
./goFileAnalysis --api-key YOUR_KEY <file_path>
```

## Configuration

Set your VirusTotal API key via `--api-key` flag or `VT_API_KEY` environment variable.

Optional polling config: `VT_MAX_POLL_ATTEMPTS` (default: 60), `VT_POLL_SLEEP_PHASE1/2/3` (default: 15/30/60s).

## Project Structure

```
├── main.go              # CLI entry point
├── checks/checks.go     # File type detection
└── vtCheck/vtCheck.go   # VirusTotal API integration
```

## Dependencies

- [h2non/filetype](https://github.com/h2non/filetype) - File type detection
- [VirusTotal/vt-go](https://github.com/VirusTotal/vt-go) - VT API client
