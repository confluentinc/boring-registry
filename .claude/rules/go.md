---
globs: "*.go"
---

# Go Conventions

## Architecture Pattern
- Domain packages (`pkg/module`, `pkg/provider`, `pkg/mirror`, `pkg/proxy`) follow go-kit service/endpoint/transport layers
- `service.go` defines the interface and implementation
- `endpoint.go` wraps service methods as go-kit endpoints with auth middleware
- `transport.go` handles HTTP routing, request decoding, and response encoding
- `middleware.go` provides logging middleware wrapping the service interface
- `errors.go` defines domain-specific error types

## Error Handling
- Use sentinel errors from `pkg/core/errors.go` (e.g., `ErrObjectNotFound`, `ErrUnauthorized`, `ErrInvalidToken`)
- HTTP status code mapping is centralized in `core.GenericError()`
- Each domain has its own `ErrorEncoder` for HTTP error responses
- Wrap errors with `fmt.Errorf("context: %w", err)` to preserve error chain for `errors.Is()`

## Testing
- Tests use `testify/assert` and `testify/require`
- Test files follow `*_test.go` naming in the same package
- Storage tests (`pkg/storage/s3_test.go`) use mocks/stubs, not real cloud services
- Mirror tests heavily use table-driven tests with subtests

## Configuration
- CLI flags are defined in `cmd/root.go` (global) and `cmd/server.go` (server-specific) using cobra/pflag
- All flags can be set via environment variables with `BORING_REGISTRY_` prefix
- Viper handles env var -> flag binding in `bindFlags()`

## Logging
- Use `log/slog` (standard library), not third-party loggers
- Structured logging with `slog.String()`, `slog.Any()`, etc.
- Debug-level logs for auth/verification flow details
- Warn-level for deprecation notices and failed verification attempts

## Dependencies
- The `vendor/` directory is committed; run `go mod vendor` after any dependency change
- Do not import packages from `vendor/` directly; use the module path
