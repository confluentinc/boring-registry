---
globs: "*.sh"
---

# Shell Script Conventions

## Scripts
- `auto-release.sh`: Automated version bumping on main. Reads commit messages to determine bump type (major/minor/patch). Creates `confluent-v*` tags.
- `helm-release.sh`: Packages and pushes Helm charts to ECR OCI registry. Uses `ENV` variable (prod/dev) for target path.

## Safety
- Both scripts use `set -e` (and `helm-release.sh` uses `set -exuo pipefail`)
- `auto-release.sh` pushes to main and creates tags -- changes here can break the release pipeline
- `helm-release.sh` syncs Chart.yaml version with INTERNAL_VERSION before packaging

## Version Tags
- Internal tags follow `confluent-v{major}.{minor}.{patch}` format
- These are distinct from upstream `v*` tags to avoid triggering GitHub Actions workflows
