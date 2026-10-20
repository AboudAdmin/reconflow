#!/usr/bin/env sh
# Builds ReconFlow from this checkout and installs the binary. User-level by default.
# Usage: ./install.sh [-d DEST_DIR] [-f]    (default DEST_DIR=$HOME/.local/bin, -f replaces an existing binary)
set -eu
dest="$HOME/.local/bin"; force=0
while getopts "d:f" o; do case $o in d) dest=$OPTARG;; f) force=1;; *) echo "usage: $0 [-d dir] [-f]" >&2; exit 2;; esac; done
[ "$(uname -s)" = "Linux" ] || { echo "ReconFlow targets Linux (Kali); detected $(uname -s)" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go is required: sudo apt install golang  (or https://go.dev/dl/)" >&2; exit 1; }
cd "$(dirname "$0")"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -o "$tmp/reconflow" ./cmd/reconflow
mkdir -p "$dest" 2>/dev/null || { echo "cannot create $dest (permissions?)" >&2; exit 1; }
if [ -e "$dest/reconflow" ] && [ "$force" -ne 1 ]; then echo "$dest/reconflow exists; re-run with -f to replace" >&2; exit 1; fi
install -m 0755 "$tmp/reconflow" "$dest/reconflow"
echo "Installed $dest/reconflow"
case ":$PATH:" in *":$dest:"*) ;; *) echo "Note: $dest is not on PATH (shell config was not modified)";; esac
echo "Optional recon tools are NOT installed. Run: reconflow tools"
