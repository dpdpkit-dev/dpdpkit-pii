import json

import pytest

from dpdpkit.pii import DatabaseScan, FileScan, build_report, diff_registry
from dpdpkit.pii.columns import classify_column
from dpdpkit.pii.database import ColumnFinding
from dpdpkit.pii.files import FileFinding

SECRET = "ABCPE1234F"


def _db_scan():
    return DatabaseScan(
        findings=[
            ColumnFinding("customers", "pan", "public", "VARCHAR", 100, {"IN_PAN": 90}, classify_column("pan"), 0.95),
            ColumnFinding("customers", "phone", "public", "VARCHAR", 100, {"IN_MOBILE": 80}, None, 0.8),
            ColumnFinding("orders", "note<b>", None, "TEXT", 10, {}, classify_column("naam"), 0.3),
        ],
        errors=["broken: OperationalError"],
    )


def test_diff_matches_with_and_without_schema_and_wildcards():
    diff = diff_registry(_db_scan(), ["Customers.PAN", "orders.*", "gone.col"])
    assert [f.column for f in diff.registered] == ["pan", "note<b>"]
    assert [f.column for f in diff.unregistered] == ["phone"]
    assert diff.unmatched == ["gone.col"]


def test_wildcard_and_schema_qualified():
    diff = diff_registry(_db_scan(), ["public.customers.*"])
    assert {f.column for f in diff.registered} == {"pan", "phone"}
    assert diff.unmatched == []


def test_file_scan_diff():
    scan = FileScan(findings=[FileFinding("kyc.csv", "pan", 5, {"IN_PAN": 5}, None, 0.9)])
    assert diff_registry(scan, ["kyc.csv:pan"]).unregistered == []
    assert len(diff_registry(scan, ["pan"]).unregistered) == 1  # files need the file name


def test_report_json_gaps_first():
    report = build_report(_db_scan(), ["customers.pan"])
    data = json.loads(report.to_json())
    assert data["summary"] == {
        "findings": 3,
        "registered": 1,
        "unregistered": 2,
        "registry_unmatched": 0,
        "errors": 1,
    }
    assert [r["registered"] for r in data["findings"]] == [False, False, True]
    assert data["findings"][2]["entities"] == {"IN_PAN": 90}


def test_markdown_and_html():
    report = build_report(_db_scan(), ["customers.pan", "x.y"])
    md = report.to_markdown()
    assert "| public.customers.phone | IN_MOBILE (80) | 100 | 0.80 | NO |" in md
    assert "Registered but not found" in md and "x.y" in md
    page = report.to_html()
    assert page.startswith("<!DOCTYPE html>")
    assert "note&lt;b&gt;" in page and "note<b>" not in page
    assert 'class="gap"' in page


def test_empty_report_and_render():
    report = build_report(DatabaseScan())
    assert "No personal data found." in report.render("md")
    assert "No personal data found." in report.render("html")
    assert json.loads(report.render("JSON"))["findings"] == []
    with pytest.raises(ValueError):
        report.render("pdf")


def test_no_values_in_reports():
    scan = FileScan(findings=[FileFinding("a.txt", "(text)", 3, {"IN_PAN": 3}, None, 0.7)])
    report = build_report(scan)
    for text in (report.to_json(), report.to_markdown(), report.to_html()):
        assert SECRET not in text
