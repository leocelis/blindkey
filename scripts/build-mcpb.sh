#!/usr/bin/env bash
# Build the MCP bundle (.mcpb) for a published release: the four release binaries, checked
# against that release's SHA256SUMS.txt, plus a launcher that picks one by OS and CPU.
# Usage: scripts/build-mcpb.sh 1.1.1 [out_dir]   ->  out_dir/blindkey-mcp-1.1.1.mcpb
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:?usage: build-mcpb.sh VERSION [OUT_DIR]}
out=${2:-dist}
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu)
base="https://github.com/leocelis/blindkey/releases/download/v${version}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/server" "$out"
curl -fsSL -o "$stage/SHA256SUMS.txt" "$base/SHA256SUMS.txt"
for t in "${targets[@]}"; do
  f="blindkey-$t"
  curl -fsSL -o "$stage/server/$f" "$base/$f"
  want=$(awk -v f="$f" '$2==f || $2=="*"f {print $1}' "$stage/SHA256SUMS.txt")
  got=$(shasum -a 256 "$stage/server/$f" | awk '{print $1}')
  [[ -n "$want" && "$want" == "$got" ]] || { echo "FAIL: checksum mismatch for $f"; exit 1; }
  chmod 0755 "$stage/server/$f"
done
install -m 0755 packaging/mcpb/run.sh "$stage/server/run.sh"
sed "s/@VERSION@/${version}/" packaging/mcpb/manifest.template.json > "$stage/manifest.json"
cp LICENSE-MIT LICENSE-APACHE "$stage/"
bundle="$out/blindkey-mcp-${version}.mcpb"
rm -f "$bundle"
(cd "$stage" && zip -qX -r - manifest.json LICENSE-MIT LICENSE-APACHE server) > "$bundle"
echo "OK: $bundle"
shasum -a 256 "$bundle"
