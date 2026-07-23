#!/usr/bin/env bash
# Reproducible test fixtures for trust-source.test.ts.
# Builds two tarballs whose layout mirrors (a) an npm @attestto/trust tarball
# (top dir "package/") and (b) a GitHub codeload tarball (top dir "attestto-trust-main/").
# Uses a tiny hand-built countries/ tree so the fixtures stay small and network-free.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Minimal country trees: two countries, each with current/manifest.json.
mk_country() {
  local root="$1" cc="$2" cn="$3"
  mkdir -p "$root/countries/$cc/current"
  cat > "$root/countries/$cc/current/manifest.json" <<JSON
{
  "country": "$cc",
  "certificates": [
    { "file": "root.pem", "sha256": "deadbeef", "subject": "$cn", "organization": "Test Org $cc", "commonName": "$cn" }
  ]
}
JSON
  cat > "$root/countries/$cc/current/root.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBFAKECERTFORTESTFIXTUREONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----
PEM
}

# npm-style tarball: top-level "package/"
npm_root="$work/package"
mk_country "$npm_root" "de" "Test Root DE"
mk_country "$npm_root" "cr" "Test Root CR"
tar -czf "$here/npm-trust.tgz" -C "$work" package

# github-style tarball: top-level "attestto-trust-main/"
gh_root="$work/attestto-trust-main"
mk_country "$gh_root" "de" "Test Root DE"
mk_country "$gh_root" "cr" "Test Root CR"
mk_country "$gh_root" "fr" "Test Root FR"
tar -czf "$here/github-trust.tar.gz" -C "$work" attestto-trust-main

echo "wrote npm-trust.tgz (de,cr) and github-trust.tar.gz (de,cr,fr)"
