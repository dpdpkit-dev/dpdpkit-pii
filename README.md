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

Planned:

- File scanner (CSV, JSON, Excel, text; folder or S3 prefix)
- Registry diff and reports (JSON, Markdown, HTML; counts only, never values)
- `dpdpkit scan` CLI and the `ghcr.io/dpdpkit-dev/scanner` image

Until then, use [`dpdpkit-fastapi`](https://github.com/dpdpkit-dev/dpdpkit-fastapi) or the core library
[`dpdpkit-core`](https://github.com/dpdpkit-dev/dpdpkit-core). Documentation:
https://dpdpkit-dev.github.io/dpdpkit-docs/dev/

## License

Apache-2.0. See [LICENSE](LICENSE). Contributions need a DCO sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
