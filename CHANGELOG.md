# Changelog

All code packages in the dpdpkit release train share one version number. This package joins the train with its
first working release.

## Unreleased

## 0.1.0a2 - 2026-11-02

### Added
- Presidio recognizers for India, from `india_recognizers()`: Aadhaar (plain, spaced or hyphenated, Verhoeff-checked),
  PAN, GSTIN (state code and check character), IFSC, UPI ID, mobile, voter ID, passport, vehicle registration
  (including BH series) and ABHA number or address.
- Column-name heuristics in English and Hinglish: `classify_column()` and `classify_columns()` flag names such as
  `aadhaar_no`, `mobile`, `dob`, `pan_card`, `naam` or `janm_tithi` with a category, a matching recognizer entity
  where one exists, and a confidence.
- Read-only database scanner, `scan_database()`: inspects tables and columns with SQLAlchemy, samples up to 500
  non-null values per column (configurable), and reports columns whose name or values look like personal data, with
  entity counts and a confidence; low-confidence findings are listed separately. It refuses a connection that can
  write (PostgreSQL, MySQL/MariaDB; unknown databases cannot be verified) unless `force=True`, sets the session to
  read-only, and never returns or logs sampled values.
- File scanner, `scan_files()`: reads CSV/TSV, JSON/JSONL, Excel (`dpdpkit-pii[excel]`) and text files from a file,
  a folder (recursive, symlinks not followed) or an S3 prefix (`dpdpkit-pii[s3]`), with include/exclude globs and a
  size cap. Reports file, field (column, JSON path or text), entity counts and a confidence, never values.
- Registry diff and reports: `diff_registry()` splits findings into registered and unregistered (gaps) and lists
  registry entries the scan did not find; `build_report()` renders JSON, Markdown or HTML with names, entity types
  and counts only.
- `dpdpkit scan` CLI (added to the `dpdpkit` command through its `dpdpkit.cli` entry point, also `python -m
  dpdpkit.pii`): scans a database URL, file, folder or S3 prefix and writes a JSON, Markdown or HTML report
  (`--sample`, `--out`, `--registry`, `--include`/`--exclude`, `--fail-on-gaps` to exit 2 on unregistered data).
  Errors print the exception class only, so connection strings and values never reach the output.
- `ghcr.io/dpdpkit-dev/scanner` image (Dockerfile and release workflow): multi-arch, non-root, with Excel, S3,
  PostgreSQL and MySQL drivers.
- `dpdpkit.pii.checksums` with the Verhoeff and GSTIN checksums.

## 0.0.1a0 - 2026-11-01

### Added
- Placeholder pre-release that reserves the package name on PyPI. It contains no functionality yet.
