# Idiomatic Go Best Practices

Follow these patterns to write clean, maintainable, and efficient Go code.

## 1. Error Handling
- **Check errors immediately:** Don't defer error handling. Handle them as soon as they occur.
- **Wrap errors with context:** Use `fmt.Errorf("context: %w", err)` to provide trace information.
- **Avoid panics:** Reserve `panic` for truly unrecoverable programmer errors (e.g., out of bounds).
- **Custom error types:** Use custom error types or sentinel errors for specific error checking.

## 2. Concurrency
- **Don't communicate by sharing memory; share memory by communicating:** Prefer channels over mutexes when possible.
- **Goroutine Leaks:** Always ensure goroutines have a clear exit strategy (e.g., using `context.Context`).
- **Sync Package:** Use `sync.WaitGroup` for waiting on multiple goroutines and `sync.Once` for one-time initialization.
- **Race Conditions:** Use the `-race` flag during testing to detect data races.

## 3. Interfaces
- **Keep interfaces small:** Prefer many small interfaces over a few large ones (e.g., `io.Reader`, `io.Writer`).
- **Accept interfaces, return structs:** This provides maximum flexibility for the caller while keeping the implementation concrete.
- **Don't export interfaces unless necessary:** Internal interfaces are often sufficient.

## 4. Naming Conventions
- **Short names for short scopes:** Use `i` for loop indices, `r` for readers, etc.
- **Package names:** Keep them short, lowercase, and singular (e.g., `net/http`, not `net/http_client`).
- **Exported symbols:** Use CamelCase (e.g., `ServeHTTP`).
- **Getter/Setter:** Omit the `Get` prefix (e.g., `Name()`, not `GetName()`).

## 5. Structs and Pointers
- **Receiver types:** Use pointer receivers if the method modifies the receiver or if the struct is large. Use value receivers for small, immutable structs.
- **Zero values:** Design structs so their zero value is useful.
- **Composition over inheritance:** Use embedding to compose behaviors.
