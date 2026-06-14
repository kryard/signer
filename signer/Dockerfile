# syntax=docker/dockerfile:1
# Kryard signer — small, static, non-root. CGO off so go-ethereum uses its
# pure-Go secp256k1 (no libsecp256k1 dependency). Runs on the private signer VM.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/signer ./cmd/signer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/signer /signer
# Internal API only — never expose publicly; reach it via the private network / mTLS.
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/signer"]
# Required env in prod: KMS_PROVIDER=aws, KMS_KEY_ID=<arn>, SIGNER_ADDR=:8081.
# ALLOW_KEY_IMPORT stays unset except during the one-time key-import window.
