# Changelog

All code packages in the dpdpkit release train share one version number. This package joins the train with its
first working release.

## Unreleased

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
- `dpdpkit.pii.checksums` with the Verhoeff and GSTIN checksums.

## 0.0.1a0 - 2026-11-01

### Added
- Placeholder pre-release that reserves the package name on PyPI. It contains no functionality yet.
