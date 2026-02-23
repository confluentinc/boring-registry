---
globs: "helm/**"
---

# Helm Chart Conventions

## Chart Structure
- Chart located at `helm/boring-registry/`
- `Chart.yaml` version is synced with `INTERNAL_VERSION` by `helm-release.sh` during CI
- Do not manually bump `Chart.yaml` version unless also updating `INTERNAL_VERSION`

## Values
- Server listens on port 5601 (main) and 7801 (telemetry) by default
- Storage backend is configured via `server.storage` (s3, gcs, or azure)
- Auth supports `createSecret` for dev or `existingSecret` for production
- Optional nginx caching proxy sidecar via `cachingProxy.enabled`

## Security
- Pod security context enforces non-root (UID 65534), drops all capabilities
- Both server and caching proxy containers follow the same security baseline
- TLS can be configured via `server.tlsKeyFile` and `server.tlsCertFile`

## Templates
- `_helpers.tpl` defines common labels and name helpers
- Deployment template handles auth secret mounting, storage args, and extra environment variables
- Audit logging args are conditionally added when `server.audit.enabled` is true

## Dashboard
- `helm/boring-registry-dashboard.json` is a Grafana dashboard (large JSON file, do not edit manually)
