# syntax=docker/dockerfile:1

# 1) Build
ARG GO_VERSION=1.25.1
FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /app

ENV CGO_ENABLED=0 GOOS=linux

# Cache de dependências
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Código-fonte
COPY . .

# Build do binário principal (usa main.go na raiz)
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -tags netgo -ldflags="-s -w" -o /out/app ./main.go

# 2) Runtime (Distroless não-root, com CA certs)
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/app /app/app

# Ajuste a porta se sua API usar outra
ENV PORT=8080
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/app/app"]