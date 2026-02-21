# boring-registry

A Terraform/OpenTofu module and provider registry server. Fork of [boring-registry/boring-registry](https://github.com/boring-registry/boring-registry) maintained by Confluent with internal CI/CD, versioning, and audit logging additions.

## Architecture

```
main.go              # Entrypoint, delegates to cmd.Execute()
cmd/
  root.go            # CLI root (cobra/viper), storage backend setup, env var binding
  server.go          # HTTP server with module/provider/mirror/proxy handlers
  upload.go          # CLI for uploading modules and providers to storage
  archive.go         # Module archive packaging for upload
pkg/
  auth/              # Auth middleware: static tokens, OIDC, Okta (deprecated)
  audit/             # S3-based audit logging for compliance
  core/              # Shared types: Module, Provider, SigningKeys, errors
  discovery/         # Terraform service discovery (/.well-known/terraform.json)
  mirror/            # Provider network mirror + pull-through mirror
  module/            # Module registry protocol (go-kit service/endpoint/transport)
  provider/          # Provider registry protocol (go-kit service/endpoint/transport)
  proxy/             # Download proxy for signed URLs
  storage/           # S3, GCS, Azure Blob storage backends
  observability/     # Prometheus metrics and HTTP instrumentation
helm/                # Helm chart for Kubernetes deployment
version/             # Build version info (injected via ldflags)
```

## Key Patterns

- **go-kit architecture**: Each domain (`module`, `provider`, `mirror`, `proxy`) follows the go-kit service/endpoint/transport pattern with logging middleware
- **Storage interface composition**: `storage.Storage` composes `module.Storage`, `provider.Storage`, `mirror.Storage`, and `proxy.Storage` interfaces
- **Auth provider chain**: Auth middleware tries issuer-matched OIDC provider first, then falls back to iterating all providers. Static tokens and OIDC/Okta cannot both be primary -- only one OIDC-type provider at a time
- **Environment variable config**: All flags use `BORING_REGISTRY_` prefix with dashes converted to underscores (e.g., `--storage-s3-bucket` -> `BORING_REGISTRY_STORAGE_S3_BUCKET`)
- **Audit logging**: Confluent addition -- logs auth events and registry access to S3 in batched JSON format

## Internal vs Upstream Versioning

- `INTERNAL_VERSION` file tracks the Confluent-internal version (separate from upstream tags)
- `auto-release.sh` bumps version based on commit message keywords (BREAKING/feat/fix), creates `confluent-v*` tags
- Upstream GitHub workflows trigger on `v*` tags; internal Semaphore pipeline uses `INTERNAL_VERSION`

## CI/CD

| System | Trigger | What it does |
|--------|---------|-------------|
| Semaphore | All branches | `go test ./...` + `make build`, then Docker build/push to ECR |
| Semaphore (main) | main only | Auto-release version bump, multi-arch Docker build (amd64/arm64), Helm chart push |
| GitHub Actions | `v*` tags | goreleaser, container push to GHCR, docs deploy (upstream workflows) |

- Docker images: `519856050701.dkr.ecr.us-west-2.amazonaws.com/docker/{prod,dev}/confluentinc/boring-registry`
- Helm charts: pushed to ECR OCI registry via `helm-release.sh`
- Images are signed with `sign-images` after push

## Common Development Commands

```bash
# Build
make build                    # go install
go build ./...                # build all packages

# Test
go test ./...                 # run all tests
go test -v ./pkg/auth/...     # test specific package

# Format
gofmt -w $(find . -name '*.go' | grep -v vendor)

# Lint
go vet $(go list ./... | grep -v vendor/)

# Run locally
go run . server --storage-s3-bucket=my-bucket --listen-address=:5601
```

## Common Pitfalls

- The `vendor/` directory is committed -- run `go mod vendor` after dependency changes
- Okta auth is deprecated; use OIDC auth (`--auth-oidc`) instead of `--auth-okta-*` flags
- Multiple OIDC providers use a semicolon-delimited format: `--auth-oidc "client_id=...;issuer=...;scopes=..."`
- The Makefile has a formatting issue (the `test` and `fmt` targets are malformed) -- use `go test ./...` directly
- `INTERNAL_VERSION` is auto-managed by CI -- do not manually edit on main unless intentional
