# Real Financial Documents Anonymization & Differential Verification Manual

This manual walks through end-to-end verification of `anon-cli` using **real public financial disclosures from SEC.gov** (SEC EDGAR XBRL multi-period financial frames and the official SEC Form 10-K PDF).

The verification contract enforces two simultaneous invariants:

1. **Complete Customer/Entity Identifier Replacement & Zero Leakage** — Every direct identifier (`cik`, `entity_name`, `accession_number`), free-text note (`preparer_note`), unclassified column (`raw_edgar_path`), telemetry baggage (`baggage.*`), and PDF metadata/interactive object (`/Info`, `/Metadata`, `/Annots`, `/AcroForm`, `/JavaScript`) is replaced, coarsened, or stripped.
2. **100% Preservation of Design, Structure, and Analytical Sense** — Row and column counts, exact `rust_decimal` monetary values (`cash_usd`), aggregate sums (`$520,621,306,888`), 1-to-1 entity bijection across periods (`CY2022Q4I` ↔ `CY2023Q4I`), per-entity Year-over-Year (YoY) cash deltas, and PDF page geometry (`19/19` pages and `/MediaBox` dimensions) remain identical to the originals.

---

## 1. Fetch Real SEC.gov Financial Disclosures

SEC.gov requires a descriptive `User-Agent` header (`AppName/Version (contact@domain)`). Run the following commands to download two consecutive years of real SEC EDGAR `CashAndCashEquivalentsAtCarryingValue` disclosures (`CY2022Q4I` and `CY2023Q4I`) and the official 19-page SEC Form 10-K PDF:

```bash
mkdir -p /tmp/sec-fin-docs

curl -sS -A "CircitAnonPipelineVerification/1.0 (security-research@circit.io)" \
  "https://data.sec.gov/api/xbrl/frames/us-gaap/CashAndCashEquivalentsAtCarryingValue/USD/CY2022Q4I.json" \
  -o /tmp/sec-fin-docs/sec_cash_2022q4.json

curl -sS -A "CircitAnonPipelineVerification/1.0 (security-research@circit.io)" \
  "https://data.sec.gov/api/xbrl/frames/us-gaap/CashAndCashEquivalentsAtCarryingValue/USD/CY2023Q4I.json" \
  -o /tmp/sec-fin-docs/sec_cash_2023q4.json

curl -sS -L -A "CircitAnonPipelineVerification/1.0 (security-research@circit.io)" \
  "https://www.sec.gov/files/form10-k.pdf" \
  -o /tmp/sec-fin-docs/sec_form10k.pdf
```

---

## 2. Build Multi-Period SQL, Telemetry, and PBC Inputs

Extract 250 real SEC filers present in both `CY2022Q4I` and `CY2023Q4I` (500 rows total) into CSV, JSONL, Telemetry JSONL, and a mixed PBC ZIP package:

```bash
python3 - << 'EOF'
import json, csv, zipfile
from pathlib import Path
from decimal import Decimal

base = Path("/tmp/sec-fin-docs")
q22 = json.loads((base / "sec_cash_2022q4.json").read_text())["data"]
q23 = json.loads((base / "sec_cash_2023q4.json").read_text())["data"]

common_ciks = sorted({r["cik"] for r in q22} & {r["cik"] for r in q23})[:250]
common_set = set(common_ciks)

rows = []
for period, dataset in [("CY2022Q4I", q22), ("CY2023Q4I", q23)]:
    for r in dataset:
        if r["cik"] in common_set:
            rows.append({
                "cik": str(r["cik"]),
                "entity_name": r["entityName"],
                "accession_number": r["accn"],
                "period_end": r["end"],
                "cash_usd": str(r["val"]),
                "currency": "USD",
                "jurisdiction": r.get("loc", "") or "US",
                "filing_frame": period,
                "preparer_note": f"Filed by {r['entityName']} (CIK {r['cik']}) under accession {r['accn']}",
                "raw_edgar_path": f"edgar/data/{r['cik']}/{r['accn']}.txt",
            })

csv_path = base / "sec_edgar_cash_snapshots.csv"
with csv_path.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

jsonl_path = base / "sec_edgar_cash_snapshots.jsonl"
with jsonl_path.open("w") as f:
    for r in rows:
        obj = dict(r)
        obj["cash_usd"] = int(r["cash_usd"]) if r["cash_usd"].lstrip("-").isdigit() else float(r["cash_usd"])
        f.write(json.dumps(obj) + "\n")

telem_path = base / "sec_edgar_telemetry.jsonl"
with telem_path.open("w") as f:
    for i, r in enumerate(rows[:100]):
        rec = {
            "timestamp": f"2024-03-15T10:{i%60:02d}:00Z",
            "service.name": "edgar-ingestion-worker",
            "http.status_code": 200,
            "cik": r["cik"],
            "entity_name": r["entity_name"],
            "baggage.filer_contact": f"cfo@{r['cik']}.example.com",
            "db.statement": f"SELECT * FROM filings WHERE entity_name = '{r['entity_name']}'",
        }
        f.write(json.dumps(rec) + "\n")

pbc_zip_path = base / "sec_pbc_package.zip"
with zipfile.ZipFile(pbc_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.write(base / "sec_form10k.pdf", arcname="form10-k.pdf")
    zf.write(csv_path, arcname="sec_edgar_cash_snapshots.csv")
    zf.write(jsonl_path, arcname="sec_edgar_cash_snapshots.jsonl")
    zf.writestr("workpaper_macro.xlsm.bin", b"\x00\x01\x02\x03UNCLASSIFIED_BINARY_BLOB")
EOF
```

---

## 3. Define the SEC Anonymization Policy (`sec_policy.yaml`)

Save the following policy to `/tmp/sec-fin-docs/sec_policy.yaml`. Note how `raw_edgar_path` is omitted altogether to exercise **default-deny withholding**, `preparer_note` is marked `suppress`, `period_end` is coarsened to `month`, and `cik`, `entity_name`, and `accession_number` use distinct `entity_type` domains:

```yaml
version: "1.0"
tenant: "sec-edgar-audit"
purpose: "financial-benchmark-verification"
fields:
  cik:
    classification: direct_identifier
    transform: pseudonymize
    entity_type: company_cik
  entity_name:
    classification: direct_identifier
    transform: pseudonymize
    entity_type: company_name
  accession_number:
    classification: direct_identifier
    transform: pseudonymize
    entity_type: sec_accession
  period_end:
    classification: quasi_identifier
    transform: coarsen
    granularity: month
  cash_usd:
    classification: financial_invariant
    transform: preserve
    precision: 2
  currency:
    classification: non_sensitive
    transform: preserve
  jurisdiction:
    classification: non_sensitive
    transform: preserve
  filing_frame:
    classification: non_sensitive
    transform: preserve
  preparer_note:
    classification: free_text
    transform: suppress
  timestamp:
    classification: non_sensitive
    transform: preserve
  service.name:
    classification: non_sensitive
    transform: preserve
  http.status_code:
    classification: non_sensitive
    transform: preserve
```

---

## 4. Run `anon-cli` Across All 4 Modalities

```bash
cd /tmp/anon-cli
rm -rf /tmp/sec-fin-docs/staging /tmp/sec-fin-docs/pbc_out /tmp/sec-fin-docs/release /tmp/sec-fin-docs/quarantine /tmp/sec-fin-docs/sec_cohort_key.json
mkdir -p /tmp/sec-fin-docs/staging /tmp/sec-fin-docs/pbc_out /tmp/sec-fin-docs/release /tmp/sec-fin-docs/quarantine

# 1. Generate 0600 cohort key
cargo run -- keygen \
  -t sec-edgar-audit \
  -p financial-benchmark-verification \
  -e company_cik \
  -v 1.0 \
  -o /tmp/sec-fin-docs/sec_cohort_key.json

# 2. Transform CSV & JSONL SQL snapshots
cargo run -- sql \
  -i /tmp/sec-fin-docs/sec_edgar_cash_snapshots.csv \
  -o /tmp/sec-fin-docs/staging/sec_edgar_cash_snapshots.csv \
  -p /tmp/sec-fin-docs/sec_policy.yaml \
  -k /tmp/sec-fin-docs/sec_cohort_key.json

cargo run -- sql \
  -i /tmp/sec-fin-docs/sec_edgar_cash_snapshots.jsonl \
  -o /tmp/sec-fin-docs/staging/sec_edgar_cash_snapshots.jsonl \
  -p /tmp/sec-fin-docs/sec_policy.yaml \
  -k /tmp/sec-fin-docs/sec_cohort_key.json

# 3. Structural PDF sanitization on SEC Form 10-K
cargo run -- pdf \
  -i /tmp/sec-fin-docs/sec_form10k.pdf \
  -o /tmp/sec-fin-docs/staging/sec_form10k.pdf \
  -p /tmp/sec-fin-docs/sec_policy.yaml

# 4. PBC Archive traversal & sub-adapter routing
cargo run -- pbc \
  -i /tmp/sec-fin-docs/sec_pbc_package.zip \
  -o /tmp/sec-fin-docs/pbc_out \
  -p /tmp/sec-fin-docs/sec_policy.yaml \
  -k /tmp/sec-fin-docs/sec_cohort_key.json

# 5. Telemetry allowlist filtering & attribute pseudonymization
cargo run -- telemetry \
  -i /tmp/sec-fin-docs/sec_edgar_telemetry.jsonl \
  -o /tmp/sec-fin-docs/staging/sec_edgar_telemetry.jsonl \
  -p /tmp/sec-fin-docs/sec_policy.yaml \
  -k /tmp/sec-fin-docs/sec_cohort_key.json
```

---

## 5. Compare Anonymized Results Against Originals

Run the differential verification script (`scripts/verify_sec_diff.py`) to compare the anonymized staging artifacts against the SEC originals:

```bash
python3 /tmp/anon-cli/scripts/verify_sec_diff.py
```

### Side-by-Side Comparison: Original vs. Anonymized Sample Row

| Field | Policy Classification | Original SEC Filing Row (`row[0]`) | Anonymized Output (`row[0]`) | Verification Check |
|---|---|---|---|---|
| `cik` | `direct_identifier` (`company_cik`) | `1750` | `64-char hex HMAC` | Replaced; identical across `CY2022Q4I` & `CY2023Q4I` |
| `entity_name` | `direct_identifier` (`company_name`) | `AAR CORP` | `64-char hex HMAC` | Replaced; zero raw company names in output |
| `accession_number` | `direct_identifier` (`sec_accession`) | `0001104659-22-128706` | `64-char hex HMAC` | Replaced; domain-separated from `cik` |
| `period_end` | `quasi_identifier` (`coarsen: month`) | `2022-11-30` | `2022-11` | Day stripped; year-month retained |
| `cash_usd` | `financial_invariant` (`preserve`) | `49000000` | `49000000` | Exact `rust_decimal` match |
| `currency` | `non_sensitive` (`preserve`) | `USD` | `USD` | Preserved verbatim |
| `jurisdiction` | `non_sensitive` (`preserve`) | `US-IL` | `US-IL` | Preserved verbatim |
| `filing_frame` | `non_sensitive` (`preserve`) | `CY2022Q4I` | `CY2022Q4I` | Preserved verbatim |
| `preparer_note` | `free_text` (`suppress`) | `Filed by AAR CORP...` | *(column omitted)* | 100% suppressed |
| `raw_edgar_path` | *(unclassified)* | `edgar/data/1750/...` | *(column omitted)* | Default-deny withheld |

### Aggregate Structural & Analytical Invariants Verified

| Invariant | Original SEC Dataset | Anonymized Output | Status |
|---|---|---|---|
| Total Rows (`CSV` & `JSONL`) | `500` | `500` | **PASS** |
| Unique Filers (`1:1` Bijection) | `250` unique CIKs | `250` unique pseudonyms | **PASS** |
| Aggregate Cash Sum (`USD`) | `$520,621,306,888` | `$520,621,306,888` | **PASS** |
| Longitudinal YoY Cash Deltas (`250` filers) | Exact vector $\Delta_1 \dots \Delta_{250}$ | Identical vector $\Delta_1 \dots \Delta_{250}$ | **PASS** |
| Raw `entity_name` / `accn` Substring Leaks | `500` present | `0` present | **PASS** |
| Telemetry Records & Baggage Stripping | `100` records (`baggage.*` + SQL present) | `100` records (`baggage.*` + SQL removed) | **PASS** |
| SEC Form 10-K PDF Page Count & `/MediaBox` | `19` pages (`49` interactive/meta objs) | `19` pages (`0` interactive/meta objs) | **PASS** |
| PBC Archive Routing & Quarantine | `3` valid + `1` unknown binary | `3` processed + `1` quarantined | **PASS** |

---

## 6. Release Gate Publication

Once `scripts/verify_sec_diff.py` exits `0` (`"status": "PASS"`), run the fail-closed release gate to publish the validated artifacts and `release-manifest.json`:

```bash
KEY_FP="$(python3 -c 'import json,hashlib; k=bytes.fromhex(json.load(open("/tmp/sec-fin-docs/sec_cohort_key.json"))["key_hex"]); print(hashlib.sha256(k).hexdigest())')"

cargo run -- release \
  -s /tmp/sec-fin-docs/staging \
  -r /tmp/sec-fin-docs/release \
  -q /tmp/sec-fin-docs/quarantine \
  --policy-version 1.0 \
  --key-fingerprint "$KEY_FP" \
  --synthetic-fixture-pass \
  --accounting-consistency-pass \
  --no-withheld-field-leak
```

---

## 7. Architectural Boundary Note: PDF Structural Sanitization vs. Visible Text

`anon-cli pdf` uses `lopdf` to sanitize the PDF object graph (stripping `/Names`, `/OpenAction`, `/AA`, `/AcroForm`, `/XFA`, `/Metadata`, `/Info`, `/Annots`, `/Filespec`, and pruning unreachable objects) while keeping all page content streams (`/Contents`) and layout geometry (`/MediaBox`) intact.

If a PDF contains customer PII inside **rendered page content streams** (visible text or embedded raster images), structural sanitization alone does not rewrite glyph streams. Per the pipeline architecture, those documents must either be quarantined under a visible-text redaction policy or routed through an external rasterize-and-rebuild stage (`OCRmyPDF` / `pdfcpu`) before release.
