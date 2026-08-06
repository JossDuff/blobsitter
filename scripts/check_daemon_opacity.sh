#!/usr/bin/env bash
# D6 — opacity: the storage daemon never parses record contents, so nothing
# app-layer may ever appear in its dependency tree. App-layer code lives in
# workspace crates (container format, materializer — M5/M6), which makes the
# invariant mechanically checkable: of all workspace members (whatever they are
# named), the only ones allowed in the daemon's normal dependency tree are the
# daemon itself and the protocol reference implementation.
set -euo pipefail
cd "$(dirname "$0")/.."

members=$(cargo metadata --format-version 1 --no-deps \
    | python3 -c "import json,sys; print('\n'.join(sorted(p['name'] for p in json.load(sys.stdin)['packages'])))")

tree=$(cargo tree -p blobsitter-daemon -e normal --prefix none | awk '{print $1}' | sort -u)

violations=$(comm -12 <(echo "$members") <(echo "$tree") \
    | grep -vx -e blobsitter-daemon -e blobsitter-reference || true)

if [ -n "$violations" ]; then
    echo "D6 VIOLATION: blobsitter-daemon depends on other workspace crates:" >&2
    echo "$violations" >&2
    echo "The daemon may depend only on blobsitter-reference (never on app-layer crates)." >&2
    exit 1
fi
echo "D6 opacity check passed: daemon depends only on the protocol reference."
