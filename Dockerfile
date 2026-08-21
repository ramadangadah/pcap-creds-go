# ---- build stage ----------------------------------------------------------
FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download all 2>/dev/null || true

COPY . .
# Regenerate go.sum against canonical module paths, then build a fully static
# binary (CGO disabled -> no libc, no libpcap needed at runtime).
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pcap-creds .

# ---- runtime stage --------------------------------------------------------
# distroless static: ~2MB, no shell, ships a nonroot user + CA certs.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /pcap-creds /pcap-creds

# Persistent state (admin account + findings) lives here; mount a volume on it.
ENV DATA_DIR=/data
VOLUME ["/data"]

EXPOSE 8000
USER nonroot:nonroot
ENTRYPOINT ["/pcap-creds"]
