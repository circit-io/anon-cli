#!/bin/sh
# anon-cli installer: fetch the latest release binary for this platform.
set -eu

REPO="circit-io/anon-cli"
TAG="${1:-latest}"

case "$(uname -s)" in
  Linux)  os=unknown-linux-gnu ;;
  Darwin) os=apple-darwin ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

[ "$os" = "unknown-linux-gnu" ] && [ "$arch" = "aarch64" ] && arch=aarch64
target="$arch-$os"

if [ "$TAG" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/anon-cli-$target.tar.gz"
else
  url="https://github.com/$REPO/releases/download/$TAG/anon-cli-$target.tar.gz"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fsSL "$url" -o "$tmp/anon-cli.tar.gz"
tar -xzf "$tmp/anon-cli.tar.gz" -C "$tmp"

dest="${ANON_CLI_INSTALL_DIR:-/usr/local/bin}"
if [ -w "$dest" ]; then
  cp "$tmp/anon-cli-$target/anon-cli" "$dest/anon-cli"
else
  sudo cp "$tmp/anon-cli-$target/anon-cli" "$dest/anon-cli"
fi
chmod 755 "$dest/anon-cli"
echo "anon-cli installed to $dest/anon-cli"
anon-cli --version || true
