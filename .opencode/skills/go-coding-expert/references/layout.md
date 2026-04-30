# Standard Go Project Layout

Guidelines for organizing a Go project to ensure clarity, maintainability, and scalability.

## 1. Top-Level Directories

### `cmd/`
- Contains entry points for the application.
- Each executable has its own subdirectory (e.g., `cmd/myapp/main.go`).
- Minimal logic: initialize configuration, set up dependencies, and start the app.

### `internal/`
- Contains code that is private to the project.
- Packages under `internal/` cannot be imported by other projects.
- This is the primary location for application-specific logic, services, and models.

### `pkg/` (Optional)
- Contains code that is safe for external projects to import.
- Use `pkg/` sparingly. Only export what is truly reusable (e.g., a shared library).

### `api/`
- Contains API definitions (e.g., OpenAPI specs, gRPC proto files).

### `assets/`
- Contains static assets (e.g., images, templates, config files).

### `configs/`
- Contains configuration file templates or default configs.

### `scripts/`
- Contains shell scripts for building, testing, and deployment.

### `test/`
- Contains integration tests and larger test suites.
- Unit tests should remain alongside the code they test (`_test.go`).

## 2. Best Practices

- **Avoid Package Sprawl:** Don't create a new package for every single file. Group related functionality.
- **Dependency Management:** Use Go Modules (`go.mod`, `go.sum`).
- **Circular Dependencies:** Avoid circular dependencies by refactoring shared logic into a separate package or interface.
- **Flat vs. Nested:** Start simple. A flat structure is often best for smaller projects. Nest as the project grows.
- **Internal vs. Exported:** Default to `internal/` to prevent external coupling. Export only when necessary.
