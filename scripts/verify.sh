#!/usr/bin/env bash
#
# Runs the assertion suite. The suite needs a gRPC path to SpiceDB for the
# relationship writes that assertions A5, A7 and A10 depend on, so this wrapper
# holds a port-forward open around it.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
trap cleanup_port_forwards EXIT

k get ns id >/dev/null 2>&1 || die "the cluster is not up. Run: make up"
# A different local port from lifecycle.sh's, which reaps stale forwards on
# :50051 — including this one, when the suite drives it as a subprocess.
port_forward id svc/spicedb 50052:50051 >/dev/null

cd "$ROOT/services"
go run ./cmd/verify \
  --gateway "${GATEWAY:-127.0.0.1:80}" \
  --spicedb localhost:50052 \
  --context "$KCTX" \
  "$@"
