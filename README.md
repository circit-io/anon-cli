# anon-cli

**Policy-driven anonymization pipeline CLI** — cohort-scoped HMAC-SHA-256 pseudonymization for SQL snapshots, PDF documents, PBC audit archives, and telemetry exports, with a fail-closed release gate.

`anon-cli` transforms sensitive financial/operational exports so that **every direct identifier is deterministically pseudonymized, quasi-identifiers coarsened, free text suppressed, and unclassified fields withheld by default** — while **financial invariants, document design, and analytical structure remain exactly intact**. Verified against **real SEC EDGAR financial disclosures** (multi-period XBRL frames + a 118-page filed annual report PDF).

![CI](https://github.com/circit-io/anon-cli/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/circit-io/anon-cli/actions/workflows/release.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

## Features

- **SQL adapter** (`sql`) — CSV / JSONL snapshot transforms. Per-field `entity_type` domain separation, Unicode NFKC canonicalization, exact `rust_decimal` financial-invariant preservation (arbitrary-precision JSON numerics), date coarsening (`day`/`month`/`year`), default-deny withholding of unclassified columns.
- **PDF adapter** (`pdf`) — structural sanitization (JavaScript, embedded files, annotations, forms, multimedia, actions, XMP/Info metadata, outlines) **plus visible-text redaction** with cross-modal pseudonym parity and kerning-preserving layout. Encrypted/malformed PDFs quarantine, never crash.
- **PBC adapter** (`pbc`) — archive traversal with magic-byte routing (PDF / nested ZIP / CSV / JSONL), Office Open XML detection, duplicate-collision protection, nested-archive atomicity, and resource limits (depth ≤ 5, ≤ 1024 entries, ≤ 64 MiB per entry).
- **Telemetry adapter** (`telemetry`) — default-deny attribute allowlist derived from policy transforms, baggage stripping, per-field entity-type pseudonymization, date coarsening.
- **Release gate** (`release`) — fail-closed: any validation failure quarantines the entire staging directory; success publishes staged artifacts + manifest (key fingerprint, never the key).
- **Crypto** — 32-byte random cohort keys, HMAC-SHA-256 with length-prefixed domain separation (`tenant:purpose:entity_type:policy_version`), key files written `0600`, policy-domain validation on load.

## Install

### Homebrew (macOS / Linux)

```bash
brew tap circit-io/anon-cli
brew install anon-cli
```

### Shell installer (prebuilt binaries)

```bash
curl -fsSL https://raw.githubusercontent.com/circit-io/anon-cli/main/install.sh | sh
```

### Cargo (from source)

```bash
cargo install anon-cli
```

### Verify

```bash
anon-cli --version
```

## Quick start

```bash
# 1. Generate a cohort key (0600 permissions, refuses to overwrite)
anon-cli keygen \
  -t sec-edgar-audit -p financial-benchmark-verification \
  -e company_cik -v 1.0 -o cohort-key.json

# 2. Transform a SQL snapshot (CSV or JSONL auto-detected)
anon-cli sql \
  -i transactions.csv -o staging/transactions.csv \
  -p policy.yaml -k cohort-key.json \
  --report-file staging/sql-report.json

# 3. Sanitize a PDF and redact visible company identifiers
anon-cli pdf \
  -i annual-report.pdf -o staging/annual-report.pdf \
  -p policy.yaml -k cohort-key.json \
  --redact 'AAR CORP:company_name' \
  --report-file staging/pdf-report.json

# 4. Process a PBC archive (mixed ZIP contents routed per type)
anon-cli pbc \
  -i pbc-package.zip -o staging/pbc/ \
  -p policy.yaml -k cohort-key.json \
  --report-file staging/pbc-report.json

# 5. Filter a telemetry export
anon-cli telemetry \
  -i telemetry.jsonl -o staging/telemetry.jsonl \
  -p policy.yaml -k cohort-key.json \
  --report-file staging/telemetry-report.json

# 6. Fail-closed release gate (requires staged *-report.json evidence)
anon-cli release \
  -s staging/ -r release/ -q quarantine/ \
  --policy-version 1.0 --key-fingerprint "$KEY_FP" \
  --synthetic-fixture-pass --accounting-consistency-pass --no-withheld-field-leak
```

## Policy YAML

```yaml
version: "1.0"
tenant: "sec-edgar-audit"
purpose: "financial-benchmark-verification"
fields:
  cik:              { classification: direct_identifier,  transform: pseudonymize, entity_type: company_cik }
  entity_name:      { classification: direct_identifier,  transform: pseudonymize, entity_type: company_name }
  period_end:       { classification: quasi_identifier,   transform: coarsen, granularity: month }
  cash_usd:         { classification: financial_invariant, transform: preserve, precision: 2 }
  preparer_note:    { classification: free_text,          transform: suppress }
  currency:         { classification: non_sensitive,      transform: preserve }
```

Classifications: `direct_identifier`, `quasi_identifier`, `financial_invariant`, `free_text`, `non_sensitive`. Transforms: `pseudonymize`, `coarsen`, `suppress`, `preserve`. **Any field not listed is withheld (default-deny).**

## Verification against real SEC EDGAR data

The pipeline is differentially verified against real public financial disclosures (SEC EDGAR `us-gaap` XBRL frames for 250 filers × 2 periods + the SEC Form 10-K PDF + a real 118-page filed annual report with visible-text redaction):

| Invariant | Result |
|---|---|
| Rows / unique-filer 1:1 bijection | 500 rows → 250 stable pseudonyms |
| Aggregate cash sum | `$520,621,306,888` — byte-identical |
| Longitudinal YoY deltas per filer | identical vectors |
| Raw company names / accession numbers in output | 0 leaks |
| PDF page geometry / financial figures after redaction | intact (visual diff) |

See [`docs/REAL-DOCS-VERIFICATION-MANUAL.md`](docs/REAL-DOCS-VERIFICATION-MANUAL.md) for the full reproduction procedure, and `scripts/verify_sec_diff.py` for the automated differential check.

## Performance

Release build on Apple Silicon (M2 Max), measured via `anon-cli bench`:

| Workload | Rows | Time | Throughput |
|---|---|---|---|
| CSV transform (single batch) | 100K | 0.52s | 191K rows/s (11.3 MB/s) |
| CSV transform (single batch) | 1M | 5.28s | 189K rows/s (11.7 MB/s) |
| CSV transform (10×10K batches) | 100K | 0.53s | 190K rows/s aggregate |
| CSV transform (10×100K batches) | 1M | 5.62s | 178K rows/s aggregate |
| Telemetry filter | — | — | ~15K records/s |
| PBC archive | 1K files (1M rows) | 5.7s | — |
| PDF sanitize + 90 redactions (118 pages) | — | 0.25s | — |

### Running batched workloads

The CLI is single-threaded by design. Scale by queueing batches across parallel processes:

```bash
# Generate a key once, reuse across all batches
anon-cli keygen -t circit -p internal-analytics -e customer -v 1.0 -o key.json

# Split a large CSV into chunks, process in parallel with xargs -P
split -l 100000 big.csv chunk_
ls chunk_* | xargs -P 8 -I{} anon-cli sql -i {} -o {}.out -p policy.yaml -k key.json

# Or use the built-in bench subcommand to measure your hardware
anon-cli bench -p policy.yaml -k key.json --rows 1000000
anon-cli bench -p policy.yaml -k key.json --rows 1000000 -b 100000  # batched mode
```

**Expected throughput by row count** (single-thread, M2 Max release build):

| Rows | Est. time | Rows/sec |
|---|---|---|
| 10K | <0.1s | ~190K |
| 100K | ~0.5s | ~190K |
| 1M | ~5.3s | ~189K |
| 10M | ~53s | ~189K |

Throughput is linear — the transform is O(n) with no per-row allocation growth. Batched mode adds ~6% overhead from file I/O between batches. For 10M+ rows, split into 100K–1M row chunks and parallelize with `xargs -P N` where N = your CPU core count.

## Security & boundary notes

- Key files are plaintext JSON with `0600` permissions — protect them like credentials; Azure Key Vault integration is a deployment concern outside this CLI.
- PDF structural sanitization + visible-text redaction covers text drawn with embedded fonts (including subsetted CID fonts via ToUnicode reverse-encoding). Text inside **raster images** cannot be redacted without OCR-based rasterization; such documents should be routed through an external rasterize-and-rebuild step (e.g. OCRmyPDF).
- Office Open XML containers (`.docx`/`.xlsx`) are detected and quarantined, not parsed.

## Development

```bash
cargo test          # 52 tests incl. real SEC EDGAR differential verification
cargo build --release
```

## License

Apache-2.0. See [LICENSE](LICENSE).
