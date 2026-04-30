# Go Security Best Practices

Guidelines for writing secure Go code and avoiding common vulnerabilities.

## 1. Input Validation and Sanitization
- **SQL Injection:** Always use parameterized queries (e.g., `db.Query("SELECT * FROM users WHERE id = ?", id)`). Never use string concatenation to build queries.
- **XSS (Cross-Site Scripting):** Use Go's `html/template` package for HTML rendering, as it automatically sanitizes data. Avoid `text/template` for HTML.
- **Command Injection:** Avoid using `os/exec` with user-supplied input. If necessary, use `exec.Command` with individual arguments rather than `bash -c`.

## 2. Sensitive Data Handling
- **Credentials:** Never hardcode secrets or API keys. Use environment variables or secret management tools.
- **Secrets Management:** Use `crypto/rand` for generating random values (e.g., salts, nonces, tokens). Never use `math/rand` for security purposes.
- **Hashing:** Use `golang.org/x/crypto/bcrypt` for hashing passwords. Never use MD5 or SHA-1 for passwords.

## 3. Web Security
- **Secure Transport:** Always use TLS/HTTPS in production. Use `crypto/tls` for fine-grained control.
- **CSRF (Cross-Site Request Forgery):** Implement CSRF tokens for sensitive state-changing operations.
- **Content Security Policy (CSP):** Use CSP headers to mitigate XSS attacks.
- **Secure Cookies:** Use `Secure`, `HttpOnly`, and `SameSite` flags for cookies.

## 4. Dependencies
- **Vulnerability Scanning:** Regularly scan dependencies for vulnerabilities using tools like `govulncheck`.
- **Minimal Dependencies:** Keep dependencies to a minimum and only use trusted libraries.
- **Checksums:** Go's `go.sum` file ensures dependency integrity.

## 5. Panic and Error Handling
- **Panic Recovery:** Use `recover` in middleware to catch panics and return a 500 status code instead of crashing the server.
- **Error Messages:** Never return internal implementation details or sensitive information (e.g., stack traces) in error responses to users.
