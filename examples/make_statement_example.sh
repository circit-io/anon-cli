#!/usr/bin/env bash
# Regenerates the README "before -> after" PDF example:
#   examples/statement_before.pdf   synthetic source document (PII in visible text + metadata + JS + annotation)
#   examples/statement_after.pdf    same document after `anon-cli pdf` (visible text pseudonymized, structure sanitized)
#   examples/statement_before.png   rendered page images used by the README
#   examples/statement_after.png
#
# Redaction specs come from examples/redactions.txt ("raw text:entity_type" per
# line), the way a real run sources them from a PII roster - not by eyeballing
# the document. Pseudonyms are cohort-key scoped: a freshly generated key
# yields different hex pseudonyms, so the committed artifacts are illustrative,
# not byte-reproducible.
set -euo pipefail

cd "$(dirname "$0")/.."

KEY="$(mktemp -d)/example-key.json"
trap 'rm -rf "$(dirname "$KEY")"' EXIT

cargo run --quiet --example make_statement_pdf

cargo run --quiet -- keygen \
  -t circit -p internal-analytics -e customer -v 1.0 -o "$KEY"

args=()
while IFS= read -r spec; do
  [ -n "$spec" ] && args+=(--redact "$spec")
done < examples/redactions.txt

cargo run --quiet -- pdf \
  -i examples/statement_before.pdf \
  -o examples/statement_after.pdf \
  -p tests/fixtures/policy_valid.yaml \
  -k "$KEY" \
  "${args[@]}"

CROP=(-png -r 96 -singlefile -x 0 -y 0 -W 816 -H 520)
pdftoppm "${CROP[@]}" examples/statement_before.pdf examples/statement_before
pdftoppm "${CROP[@]}" examples/statement_after.pdf examples/statement_after

echo "regenerated examples/statement_{before,after}.{pdf,png}"
