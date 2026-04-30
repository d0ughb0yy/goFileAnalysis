---
name: go-coding-expert
description: Expert guidance on writing idiomatic Go, implementing security best practices, and following standard project layouts. Use this skill when building or refactoring Go applications to ensure high quality, maintainability, and security.
---

# Go Coding Expert

## Overview

This skill provides comprehensive guidance for writing high-quality Go code using the standard library. It focuses on idiomatic patterns, security best practices, and the standard project layout to ensure your Go applications are robust and maintainable.

## Guidelines

### 1. Idiomatic Go
Focus on simplicity, readability, and efficient concurrency. Avoid over-engineering and prefer small, focused components.
- See [references/idioms.md](references/idioms.md) for detailed idiomatic patterns.

### 2. Security Best Practices
Prioritize security from the start. Sanitize inputs, handle sensitive data carefully, and keep dependencies minimal.
- See [references/security.md](references/security.md) for general security considerations and mitigations.

### 3. Project Structure
Follow the community-standard layout to ensure your project is easy to navigate and scale.
- See [references/layout.md](references/layout.md) for the standard project layout and best practices.

## Usage

When working on a Go project, use this skill to:
- **Design:** Plan your project's structure following the standard layout.
- **Implement:** Apply idiomatic patterns for error handling, concurrency, and interfaces.
- **Secure:** Validate inputs and handle sensitive data using recommended practices.
- **Review:** Audit existing code for idiomatic quality and potential security vulnerabilities.

### Quick Tips:
- Check errors immediately and wrap them with context.
- Use `crypto/rand` for secure random generation.
- Default to `internal/` for application-specific logic.
- Keep interfaces small and focused.
