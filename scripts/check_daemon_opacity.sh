#!/usr/bin/env bash
# D6 — opacity: the storage daemon never parses record contents, so nothing
# app-layer may ever appear in its dependency tree. App-layer code lives in
# workspace crates (container format, materializer — M5/M6), which makes the
# invariant mechanically checkable: the only workspace crate the daemon may
# depend on is the protocol reference implementation.
set -euo pipefail
cd "$(dirname "$0")/.."

allowed="blobsitter-daemon
blobsitter-reference"

found=$(cargo tree -p blobsitter-daemon -e normal --prefix none \
    | awk '{print $1}' | grep '^blobsitter-' | sort -u)

if [ "$found" != "$allowed" ]; then
    echo "D6 VIOLATION: blobsitter-daemon's workspace dependencies changed:" >&2
    diff <(echo "$allowed") <(echo "$found") >&2 || true
    echo "The daemon may depend only on blobsitter-reference (never on app-layer crates)." >&2
    exit 1
fi
echo "D6 opacity check passed: daemon depends only on the protocol reference."
