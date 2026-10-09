# syntax=docker/dockerfile:1
# The sneakers-migrate image. Build from the repository root:
#   docker build -f migrate/Dockerfile -t sneakers-migrate .
ARG GO_VERSION=1.26.9
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gen/ gen/
COPY migrate/ migrate/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/Sneakers-PAM/sneakers-release/migrate/internal/commands.Version=${VERSION}" \
      -o /out/sneakers-migrate ./migrate/cmd/sneakers-migrate

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/sneakers-migrate /sneakers-migrate
USER nonroot:nonroot
ENTRYPOINT ["/sneakers-migrate"]
