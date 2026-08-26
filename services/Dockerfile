# One image, every binary.
#
# The MVP has seven Go programs that share a module. Building seven images would
# mean seven layer caches, seven `kind load` transfers and seven things to keep
# in step; each Deployment instead selects its binary with `command`. At this
# size that is strictly less to go wrong, and the boundary that matters —
# separate ServiceAccounts, so separate SPIFFE identities (M-010) — is enforced
# by Kubernetes, not by the image.

FROM golang:1.26.6-alpine AS build
WORKDIR /src

# Dependencies first, so editing application code does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off and a trimmed path give a static binary and reproducible builds.
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

# The route configuration is validated at image build time. A configuration
# that would stop ext-authz starting fails the build instead (M-006 in CI form).
COPY config/ext-authz.yaml /tmp/ext-authz.yaml
RUN /out/configcheck /tmp/ext-authz.yaml > /dev/null

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata curl \
 && adduser -D -u 10001 gerege
COPY --from=build /out/ /app/
USER 10001

# No ADDR/HEALTH_ADDR defaults here. One image holds seven programs that listen
# on different ports — the demo services on 8080/8081, ext-authz on
# 9001/9002/9003 — and an image-wide default silently overrides the right one
# for six of them. Each binary carries its own defaults; a Deployment that wants
# something else sets it explicitly.
EXPOSE 8080 8081 9001 9002 9003
ENTRYPOINT ["/app/ext-authz"]
