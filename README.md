# dpdpkit-pii

Personal-data discovery for [dpdpkit](https://github.com/dpdpkit-dev). It will find personal data in your databases and files and compare it with your dpdpkit registry, reporting counts only.

> **Disclaimer.** dpdpkit is software that helps you implement obligations under India's Digital Personal
> Data Protection Act, 2023 and the DPDP Rules, 2025. It does not provide legal advice and does not
> guarantee compliance. Decisions about notices, purposes, retention and incident reporting must be made
> by you or your counsel.

## Status

**Not usable yet.** Version 0.0.1a0 is an empty pre-release that reserves the name on PyPI. The first working
release is planned for milestone v0.5 (planned for June 2027); the work is tracked as PII-01 to PII-08 in the dpdpkit task sheet.

In the repository now (unreleased): Presidio recognizers for India: Aadhaar (with Verhoeff check), PAN, GSTIN,
IFSC, UPI, mobile, voter ID, passport, vehicle registration, ABHA.

```python
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from dpdpkit.pii import india_recognizers

registry = RecognizerRegistry()
for recognizer in india_recognizers():
    registry.add_recognizer(recognizer)
results = AnalyzerEngine(registry=registry).analyze(text="PAN ABCPE1234F", language="en")
```

Column-name heuristics for English and Hinglish names (a hint from the name only, with a confidence):

```python
from dpdpkit.pii import classify_column

classify_column("aadhaar_no")  # category "aadhaar", entity "IN_AADHAAR"
classify_column("janm_tithi")  # category "dob"
```

Read-only database scanner. It refuses a connection that can write unless `force=True`, samples at most `sample`
values per column, and reports columns and counts, never values:

```python
from dpdpkit.pii import scan_database

scan = scan_database("postgresql://readonly@host/db", sample=500)
for f in scan.confident:
    print(f.qualified_name, f.entities, f.confidence)  # e.g. customers.pan {'IN_PAN': 212} 0.95
```

File scanner for CSV, JSON, Excel and text files in a folder or under an S3 prefix (Excel needs
`dpdpkit-pii[excel]`, S3 needs `dpdpkit-pii[s3]`). It only reads, does not follow symlinks, and reports files, fields
and counts, never values:

```python
from dpdpkit.pii import scan_files

scan = scan_files("s3://my-bucket/exports/", sample=500, exclude=["*.log"])
for f in scan.confident:
    print(f.qualified_name, f.entities, f.confidence)  # e.g. s3://my-bucket/exports/kyc.csv:pan {'IN_PAN': 212} 0.95
```

Registry diff and reports. Pass the names you have registered (`table.column`, `schema.table.column` or
`file:field`, with `*` wildcards); unregistered findings are the gaps and are listed first. Reports hold names,
entity types and counts only:

```python
from dpdpkit.pii import build_report

report = build_report(scan, registry=["customers.pan", "customers.phone", "orders.*"])
print(report.to_markdown())  # or report.to_json(), report.to_html(), report.render("md")
```

Command line (adds `dpdpkit scan` to the `dpdpkit` command) and container image:

```shell
dpdpkit scan postgresql://readonly@host/db --sample 500 --registry registry.txt --out report.html
dpdpkit scan ./exports --format json --fail-on-gaps   # exit 2 if unregistered personal data is found
docker run --read-only --tmpfs /tmp ghcr.io/dpdpkit-dev/scanner postgresql://readonly@host/db
```

The target is a database URL, a file, a folder or an `s3://` prefix. The registry file is a JSON array or one name
per line. The format comes from `--format`, else the `--out` suffix, else Markdown.

Until then, use [`dpdpkit-fastapi`](https://github.com/dpdpkit-dev/dpdpkit-fastapi) or the core library
[`dpdpkit-core`](https://github.com/dpdpkit-dev/dpdpkit-core). Documentation:
https://dpdpkit-dev.github.io/dpdpkit-docs/dev/

## License

Apache-2.0. See [LICENSE](LICENSE). Contributions need a DCO sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
