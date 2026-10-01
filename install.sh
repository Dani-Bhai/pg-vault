#!/bin/sh
# Install pgvault — encrypted PostgreSQL backups.
#
# From a clone:
#   ./install.sh
#
# Directly from GitHub:
#   curl -fsSL https://raw.githubusercontent.com/Dani-Bhai/pg-vault/master/install.sh | sh
#
# Inside the repository the script builds from source; anywhere else it
# downloads the release asset for this OS/architecture, falling back to
# "go install" when no release exists yet.
#
# Environment:
#   BINDIR   where to put the binary (default: ~/.local/bin)
#   VERSION  release tag to install (default: latest)

set -eu

REPO="Dani-Bhai/pg-vault"
BIN="pgvault"
BINDIR="${BINDIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
err() { printf 'pgvault-install: error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Find the source checkout this script belongs to, when there is one.
script_dir=""
case "$0" in
*/*) script_dir=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd) || script_dir="" ;;
esac
src_root=""
if [ -n "$script_dir" ] && [ -f "$script_dir/go.mod" ] && [ -d "$script_dir/cmd/$BIN" ]; then
  src_root="$script_dir"
elif [ -f ./go.mod ] && [ -d "./cmd/$BIN" ] && grep -q "^module github.com/$REPO\$" ./go.mod 2>/dev/null; then
  src_root=$(pwd)
fi

mkdir -p "$BINDIR"
[ -w "$BINDIR" ] || err "$BINDIR is not writable (set BINDIR to a writable directory, e.g. BINDIR=/usr/local/bin sudo sh)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

install_binary() {
  cp "$1" "$BINDIR/$BIN"
  chmod 0755 "$BINDIR/$BIN"
  say "installed $BINDIR/$BIN"
  case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *)
    say "note: $BINDIR is not in your PATH; add it with:"
    say "  export PATH=\"$BINDIR:\$PATH\""
    ;;
  esac
}

# 1. Build from source when run inside a checkout.
if [ -n "$src_root" ]; then
  have go || err "building from source needs Go: https://go.dev/dl/"
  say "building $BIN from source ($src_root)"
  (cd "$src_root" && go build -trimpath -o "$tmp/$BIN" "./cmd/$BIN")
  install_binary "$tmp/$BIN"
  exit 0
fi

# 2. Otherwise download the release asset for this platform.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
linux | darwin) ;;
*) err "unsupported OS: $os (see https://github.com/$REPO/releases)" ;;
esac
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) err "unsupported architecture: $arch (see https://github.com/$REPO/releases)" ;;
esac

version="${VERSION:-latest}"
if [ "$version" = latest ]; then
  asset_url="https://github.com/$REPO/releases/latest/download"
else
  asset_url="https://github.com/$REPO/releases/download/$version"
fi
asset="${BIN}_${os}_${arch}.tar.gz"
tarball="$BIN.tar.gz"

downloaded=0
if have curl; then
  curl -fsSL --retry 3 -o "$tmp/$tarball" "$asset_url/$asset" && downloaded=1 || true
  curl -fsSL -o "$tmp/checksums.txt" "$asset_url/checksums.txt" 2>/dev/null || true
elif have wget; then
  wget -q -O "$tmp/$tarball" "$asset_url/$asset" && downloaded=1 || true
  wget -q -O "$tmp/checksums.txt" "$asset_url/checksums.txt" 2>/dev/null || true
fi

if [ "$downloaded" -eq 1 ]; then
  if [ -s "$tmp/checksums.txt" ]; then
    want=$(grep " $asset\$" "$tmp/checksums.txt" | awk '{print $1}' | head -n1)
    if [ -n "$want" ]; then
      got=""
      if have sha256sum; then
        got=$(sha256sum "$tmp/$tarball" | awk '{print $1}')
      elif have shasum; then
        got=$(shasum -a 256 "$tmp/$tarball" | awk '{print $1}')
      fi
      if [ -n "$got" ] && [ "$got" != "$want" ]; then
        err "checksum mismatch for $asset"
      fi
      [ -z "$got" ] || say "checksum verified"
    fi
  fi
  tar -xzf "$tmp/$tarball" -C "$tmp"
  install_binary "$tmp/$BIN"
  exit 0
fi

# 3. No release asset (yet): fall back to the Go toolchain.
if have go; then
  say "no release asset for $os/$arch; installing with 'go install'"
  GOBIN="$BINDIR" go install "github.com/$REPO/cmd/$BIN@$version"
  say "installed $BINDIR/$BIN"
  exit 0
fi

err "could not download a release for $os/$arch and Go is not installed"
