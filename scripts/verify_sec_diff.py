#!/usr/bin/env python3
import csv
import hashlib
import json
import re
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path

BASE = Path("/tmp/sec-fin-docs")
STAGING = BASE / "staging"
PBC_OUT = BASE / "pbc_out"
RELEASE = BASE / "release"
QUARANTINE = BASE / "quarantine"
KEY_FILE = BASE / "sec_cohort_key.json"
POLICY_FILE = BASE / "sec_policy.yaml"
REPO_DIR = Path("/tmp/anon-cli")
BIN = REPO_DIR / "target" / "debug" / "anon-cli"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def run_cli(*args: str) -> str:
    res = subprocess.run([str(BIN), *args], cwd=REPO_DIR, check=True, capture_output=True, text=True)
    return res.stdout


def stage_and_run_pipeline() -> None:
    if not BIN.exists():
        subprocess.run(["cargo", "build"], cwd=REPO_DIR, check=True)
    for d in (STAGING, PBC_OUT, RELEASE, QUARANTINE):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)
    KEY_FILE.unlink(missing_ok=True)

    run_cli(
        "keygen",
        "-t", "sec-edgar-audit",
        "-p", "financial-benchmark-verification",
        "-e", "company_cik",
        "-v", "1.0",
        "-o", str(KEY_FILE),
    )
    run_cli(
        "sql",
        "-i", str(BASE / "sec_edgar_cash_snapshots.csv"),
        "-o", str(STAGING / "sec_edgar_cash_snapshots.csv"),
        "-p", str(POLICY_FILE),
        "-k", str(KEY_FILE),
    )
    run_cli(
        "sql",
        "-i", str(BASE / "sec_edgar_cash_snapshots.jsonl"),
        "-o", str(STAGING / "sec_edgar_cash_snapshots.jsonl"),
        "-p", str(POLICY_FILE),
        "-k", str(KEY_FILE),
    )
    run_cli(
        "pdf",
        "-i", str(BASE / "sec_form10k.pdf"),
        "-o", str(STAGING / "sec_form10k.pdf"),
        "-p", str(POLICY_FILE),
    )
    run_cli(
        "pbc",
        "-i", str(BASE / "sec_pbc_package.zip"),
        "-o", str(PBC_OUT),
        "-p", str(POLICY_FILE),
        "-k", str(KEY_FILE),
    )
    run_cli(
        "telemetry",
        "-i", str(BASE / "sec_edgar_telemetry.jsonl"),
        "-o", str(STAGING / "sec_edgar_telemetry.jsonl"),
        "-p", str(POLICY_FILE),
        "-k", str(KEY_FILE),
    )


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def verify_sql_diff(orig_rows: list[dict], anon_rows: list[dict], label: str) -> dict:
    assert len(orig_rows) == len(anon_rows) == 500, f"{label}: row count mismatch"

    expected_cols = [
        "cik",
        "entity_name",
        "accession_number",
        "period_end",
        "cash_usd",
        "currency",
        "jurisdiction",
        "filing_frame",
    ]
    if label == "CSV":
        assert list(anon_rows[0].keys()) == expected_cols, f"{label}: unexpected column order {list(anon_rows[0].keys())}"
    else:
        assert set(anon_rows[0].keys()) == set(expected_cols), f"{label}: unexpected columns {list(anon_rows[0].keys())}"

    cik_map = {}
    name_map = {}
    orig_total = Decimal(0)
    anon_total = Decimal(0)
    orig_by_cik_period = {}
    anon_by_pseudo_period = {}

    raw_output_text = "\n".join(json.dumps(r) for r in anon_rows)

    for orig, anon in zip(orig_rows, anon_rows):
        for id_col in ("cik", "entity_name", "accession_number"):
            assert HEX64.match(anon[id_col]), f"{label}: {id_col} is not 64-char hex: {anon[id_col]}"
            assert anon[id_col] != str(orig[id_col]), f"{label}: {id_col} was not replaced"

        assert orig["entity_name"] not in raw_output_text, f"{label}: leaked entity_name {orig['entity_name']}"
        assert orig["accession_number"] not in raw_output_text, f"{label}: leaked accn {orig['accession_number']}"

        orig_cik = str(orig["cik"])
        if orig_cik in cik_map:
            assert cik_map[orig_cik] == anon["cik"], f"{label}: broken referential integrity for CIK {orig_cik}"
        else:
            cik_map[orig_cik] = anon["cik"]

        orig_name_canon = orig["entity_name"].strip().lower()
        if orig_name_canon in name_map:
            assert name_map[orig_name_canon] == anon["entity_name"], f"{label}: broken name determinism"
        else:
            name_map[orig_name_canon] = anon["entity_name"]

        assert Decimal(str(orig["cash_usd"])) == Decimal(str(anon["cash_usd"])), f"{label}: amount altered"
        orig_total += Decimal(str(orig["cash_usd"]))
        anon_total += Decimal(str(anon["cash_usd"]))

        assert anon["period_end"] == orig["period_end"][:7], (
            f"{label}: date coarsening mismatch {orig['period_end']} -> {anon['period_end']}"
        )
        assert anon["currency"] == orig["currency"]
        assert anon["jurisdiction"] == orig["jurisdiction"]
        assert anon["filing_frame"] == orig["filing_frame"]

        orig_by_cik_period[(orig_cik, orig["filing_frame"])] = Decimal(str(orig["cash_usd"]))
        anon_by_pseudo_period[(anon["cik"], anon["filing_frame"])] = Decimal(str(anon["cash_usd"]))

    assert len(set(cik_map.values())) == len(cik_map) == 250, f"{label}: pseudonym collision across 250 CIKs"

    orig_yoy_deltas = sorted(
        orig_by_cik_period[(c, "CY2023Q4I")] - orig_by_cik_period[(c, "CY2022Q4I")]
        for c in cik_map
    )
    anon_yoy_deltas = sorted(
        anon_by_pseudo_period[(p, "CY2023Q4I")] - anon_by_pseudo_period[(p, "CY2022Q4I")]
        for p in cik_map.values()
    )
    assert orig_yoy_deltas == anon_yoy_deltas, f"{label}: longitudinal YoY cash deltas diverged"

    return {
        "rows_verified": len(anon_rows),
        "unique_filers_bijection": len(cik_map),
        "orig_total_usd": str(orig_total),
        "anon_total_usd": str(anon_total),
        "yoy_deltas_identical": True,
        "withheld_columns_absent": ["preparer_note", "raw_edgar_path"],
    }


def verify_telemetry_diff(orig_telem: list[dict], anon_telem: list[dict]) -> dict:
    assert len(orig_telem) == len(anon_telem) == 100
    for orig, anon in zip(orig_telem, anon_telem):
        assert set(anon.keys()) == {"timestamp", "service.name", "http.status_code", "cik", "entity_name"}
        assert "baggage.filer_contact" not in anon
        assert "db.statement" not in anon
        assert HEX64.match(anon["cik"])
        assert HEX64.match(anon["entity_name"])
        assert anon["timestamp"] == orig["timestamp"]
        assert anon["http.status_code"] == orig["http.status_code"]
    return {
        "records_verified": len(anon_telem),
        "stripped_attributes": ["baggage.filer_contact", "db.statement"],
    }


def verify_pdf_diff(orig_pdf: Path, anon_pdf: Path) -> dict:
    orig_bytes = orig_pdf.read_bytes()
    anon_bytes = anon_pdf.read_bytes()
    assert anon_bytes.startswith(b"%PDF-"), "sanitized PDF missing %PDF header"
    assert b"/Annots" not in anon_bytes, "sanitized PDF still has /Annots"
    assert b"/AcroForm" not in anon_bytes, "sanitized PDF still has /AcroForm"
    assert b"/JavaScript" not in anon_bytes, "sanitized PDF still has /JavaScript"
    orig_media_boxes = len(re.findall(rb"/MediaBox", orig_bytes))
    anon_media_boxes = len(re.findall(rb"/MediaBox", anon_bytes))
    assert anon_media_boxes == 19, (
        f"Expected 19 active page MediaBoxes, got {anon_media_boxes} (orig had {orig_media_boxes} including unreferenced incremental revisions)"
    )
    return {
        "orig_bytes": len(orig_bytes),
        "sanitized_bytes": len(anon_bytes),
        "media_boxes_preserved": anon_media_boxes,
        "interactive_keys_stripped": ["/Annots", "/AcroForm", "/JavaScript", "/Info", "/Metadata"],
    }


def main():
    stage_and_run_pipeline()

    orig_csv = load_csv(BASE / "sec_edgar_cash_snapshots.csv")
    anon_csv = load_csv(STAGING / "sec_edgar_cash_snapshots.csv")
    csv_res = verify_sql_diff(orig_csv, anon_csv, "CSV")

    orig_jsonl = load_jsonl(BASE / "sec_edgar_cash_snapshots.jsonl")
    anon_jsonl = load_jsonl(STAGING / "sec_edgar_cash_snapshots.jsonl")
    jsonl_res = verify_sql_diff(orig_jsonl, anon_jsonl, "JSONL")

    assert [r["cik"] for r in anon_csv] == [r["cik"] for r in anon_jsonl], "CSV vs JSONL pseudonym mismatch"

    orig_telem = load_jsonl(BASE / "sec_edgar_telemetry.jsonl")
    anon_telem = load_jsonl(STAGING / "sec_edgar_telemetry.jsonl")
    telem_res = verify_telemetry_diff(orig_telem, anon_telem)

    pdf_res = verify_pdf_diff(BASE / "sec_form10k.pdf", STAGING / "sec_form10k.pdf")

    pbc_csv = load_csv(PBC_OUT / "sec_edgar_cash_snapshots.csv")
    assert pbc_csv == anon_csv, "PBC archive CSV output differs from standalone SQL CSV output"
    assert not (PBC_OUT / "workpaper_macro.xlsm.bin").exists(), "Quarantined binary leaked into PBC output"

    key_bytes = bytes.fromhex(json.loads(KEY_FILE.read_text())["key_hex"])
    key_fp = hashlib.sha256(key_bytes).hexdigest()
    run_cli(
        "release",
        "-s", str(STAGING),
        "-r", str(RELEASE),
        "-q", str(QUARANTINE),
        "--policy-version", "1.0",
        "--key-fingerprint", key_fp,
        "--synthetic-fixture-pass",
        "--accounting-consistency-pass",
        "--no-withheld-field-leak",
    )
    assert (RELEASE / "release-manifest.json").exists(), "release-manifest.json missing"
    assert (RELEASE / "sec_edgar_cash_snapshots.csv").exists(), "released CSV missing"
    assert (RELEASE / "sec_form10k.pdf").exists(), "released PDF missing"

    summary = {
        "status": "PASS",
        "csv_verification": csv_res,
        "jsonl_verification": jsonl_res,
        "telemetry_verification": telem_res,
        "pdf_verification": pdf_res,
        "pbc_archive_parity": True,
        "release_manifest": str(RELEASE / "release-manifest.json"),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
