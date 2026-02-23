---
globs: ".semaphore/*.yml,.semaphore/*.yaml"
---

# Semaphore Pipeline Conventions

## Pipeline Structure
- Single pipeline in `.semaphore/semaphore.yml` with block-level dependencies
- `Test & Build` runs first on all branches, subsequent blocks depend on it
- Main branch: auto-release -> multi-arch Docker builds (amd64 + arm64) -> manifest creation -> helm push
- Non-main branches: Docker builds to dev ECR path, dev helm chart push

## Managed Sections
- Per `service.yml`, Semaphore manages: `version`, `name`, `agent`, `global_job_config`
- Do not manually modify these sections; they are overwritten by automation

## Build Details
- Go version is set explicitly in CI with `sem-version go` (currently 1.23.10)
- Docker builds use `--build-arg` for VERSION, GIT_COMMIT, BUILD_TIMESTAMP (ldflags injection)
- Images are signed after push with `sign-images` utility
- Multi-arch manifests combine amd64 and arm64 images

## ECR Details
- Registry: `519856050701.dkr.ecr.us-west-2.amazonaws.com`
- Prod images: `docker/prod/confluentinc/boring-registry`
- Dev images: `docker/dev/confluentinc/boring-registry`
- Dev image tags use branch name + short SHA

## Key Scripts
- `auto-release.sh`: Bumps `INTERNAL_VERSION`, creates `confluent-v*` git tag, pushes to main
- `helm-release.sh`: Packages and pushes Helm chart to ECR OCI registry
