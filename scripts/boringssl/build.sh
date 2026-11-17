#!/usr/bin/env bash
# Build BoringSSL with Chromium's extension 4832 (server padding request).
#
# btls-sys builds its own BoringSSL from a crates.io copy and applies its
# patches there. Upstream BoringSSL has no 4832 - it is a Chromium-only
# extension - so a ClientHello built on stock BoringSSL always misses it and
# its JA4 never matches a real Chrome. This script produces a source tree with
# btls's patches plus scripts/boringssl/chrome4832.patch, and prints the two
# environment variables btls-sys reads.
#
# Usage:  scripts/boringssl/build.sh [output-dir]
# Then:   eval "$(scripts/boringssl/build.sh --env)"   before cargo build
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${1:-$ROOT/target/boringssl-chrome}
BTLS_SYS=$(ls -d "$HOME"/.cargo/registry/src/*/btls-sys-0.5.6 2>/dev/null | head -1)

if [[ "${1:-}" == "--env" ]]; then
  cat <<EOF
export BORING_BSSL_SOURCE_PATH=$OUT
export BORING_BSSL_INCLUDE_PATH=$OUT/include
export BORING_BSSL_ASSUME_PATCHED=1
EOF
  exit 0
fi

if [[ -z "$BTLS_SYS" ]]; then
  echo "btls-sys-0.5.6 is not in the cargo registry; run 'cargo fetch' first" >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
cp -r "$BTLS_SYS/deps/boringssl/." "$OUT/"
cd "$OUT"
git init -q .
git add -A
git -c user.email=build@local -c user.name=build commit -qm base

for patch in boring-pq boringssl boringssl-loongarch boringssl-windows; do
  git apply --whitespace=fix "$BTLS_SYS/patches/$patch.patch"
done

git add -A
git -c user.email=build@local -c user.name=build commit -qm btls-patched

git apply --whitespace=fix "$HERE/chrome4832.patch"

echo "BoringSSL source with extension 4832 is at: $OUT"
echo
echo "Build the crate with:"
echo "  $HERE/build.sh --env   # prints the variables to eval"
