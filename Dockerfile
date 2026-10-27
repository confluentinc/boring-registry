# ARG before first stage to share the value across multiple stages
ARG BASEDIR=/go/src/github.com/boring-registry/boring-registry

FROM golang:1.26.6 AS build

ARG VERSION
ARG GIT_COMMIT
ARG BUILD_TIMESTAMP
ARG BASEDIR # use the default value

WORKDIR ${BASEDIR}

COPY . ${BASEDIR}
RUN CGO_ENABLED=0 go build -ldflags "-s -w \
    -X github.com/boring-registry/boring-registry/version.Version=${VERSION} \
    -X github.com/boring-registry/boring-registry/version.Commit=${GIT_COMMIT} \
    -X github.com/boring-registry/boring-registry/version.Date=${BUILD_TIMESTAMP}"

# Pinned to the multi-arch index digest so the OS packages in the image (ca-certificates, tzdata) change
# only through a reviewed Renovate digest bump, not whatever the build agent resolves the tag to.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG BASEDIR
COPY --from=build ${BASEDIR}/boring-registry /

ENTRYPOINT ["/boring-registry"]
CMD ["server"]
