"""Read-only file scanner: CSV, JSON, Excel and text files in a folder or under an S3 prefix.

Files are only read, never modified. Sampled values are checked in memory against the India recognizers and then
dropped; a finding holds the file, the field (column, JSON path or text), the entity types and *counts*, never a
value, and error messages never include values. Excel needs ``openpyxl`` and S3 needs ``boto3``; both are optional
extras (``dpdpkit-pii[excel]``, ``dpdpkit-pii[s3]``).
"""

from __future__ import annotations

import csv
import fnmatch
import io
import json
import os
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from presidio_analyzer import PatternRecognizer

from dpdpkit.pii.columns import ColumnMatch, classify_column
from dpdpkit.pii.database import DEFAULT_SAMPLE, LOW_CONFIDENCE, _confidence, _count_hits
from dpdpkit.pii.recognizers import india_recognizers

DEFAULT_MAX_BYTES = 20 * 1024 * 1024  # larger files are read up to this size (CSV, text) or skipped (JSON, Excel)
DEFAULT_TEXT_LINES = 10_000  # text files are scanned line by line, up to this many non-empty lines

_ROW_FACTOR = 10  # a table is read for at most ``sample * _ROW_FACTOR`` rows, so sparse columns still end the scan
_TEXT_CONFIDENCE = 0.7  # free text has no column name or value ratio to go on; any recognizer hit is a real hit
_CSV = {".csv": ",", ".tsv": "\t"}
_JSON = {".json", ".jsonl", ".ndjson"}
_EXCEL = {".xlsx", ".xlsm"}
_TEXT = {".txt", ".log", ".md", ".text"}


@dataclass(frozen=True)
class FileFinding:
    """A field in a file that looks like it holds personal data.

    ``field`` is the CSV/Excel column (``Sheet/column`` for Excel), the JSON path (``customers[].pan``) or
    ``(text)``. ``entities`` maps a recognizer entity to the number of sampled values it matched.
    """

    file: str
    field: str
    sampled: int
    entities: dict[str, int]
    name_match: ColumnMatch | None
    confidence: float

    @property
    def qualified_name(self) -> str:
        return f"{self.file}:{self.field}"


@dataclass
class FileScan:
    """Result of a scan. Holds counts and file and field names only."""

    findings: list[FileFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0  # unsupported type, or excluded
    errors: list[str] = field(default_factory=list)

    @property
    def confident(self) -> list[FileFinding]:
        return [f for f in self.findings if f.confidence >= LOW_CONFIDENCE]

    @property
    def low_confidence(self) -> list[FileFinding]:
        return [f for f in self.findings if f.confidence < LOW_CONFIDENCE]


@dataclass(frozen=True)
class _Source:
    name: str
    suffix: str
    data: bytes
    truncated: bool


def scan_files(
    target: str | os.PathLike[str],
    *,
    sample: int = DEFAULT_SAMPLE,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    text_lines: int = DEFAULT_TEXT_LINES,
    recognizers: Sequence[PatternRecognizer] | None = None,
    s3_client: Any = None,
) -> FileScan:
    """Scan a file, a folder (recursively) or an S3 prefix (``s3://bucket/prefix``) for personal data.

    At most ``sample`` non-empty values are read per column or JSON path, and at most ``text_lines`` lines per text
    file. ``include`` and ``exclude`` are glob patterns matched against the file name and the path relative to the
    target. Symbolic links are not followed. Files over ``max_bytes`` are read only up to that size; JSON and Excel
    cannot be read partially, so they are skipped with an error. ``s3_client`` is a boto3 S3 client (default: one
    built from the environment's credentials, used only for listing and reading objects).
    """
    if sample < 1:
        raise ValueError("sample must be at least 1")
    active = list(recognizers) if recognizers is not None else india_recognizers()
    wanted = list(include) if include is not None else None
    skipped = list(exclude)
    result = FileScan()

    if isinstance(target, str) and target.startswith("s3://"):
        sources = _s3_sources(target, s3_client, max_bytes, wanted, skipped, result)
    else:
        sources = _local_sources(Path(target), max_bytes, wanted, skipped, result)

    for source in sources:
        try:
            findings = _scan_source(source, sample, text_lines, active)
        except Exception as exc:
            # Only the exception class: parser messages can quote the offending content.
            result.errors.append(f"{source.name}: {type(exc).__name__}")
            continue
        result.files_scanned += 1
        result.findings.extend(findings)
    return result


def _matches(name: str, relative: str, wanted: list[str] | None, skipped: list[str]) -> bool:
    base = PurePosixPath(relative).name

    def hit(patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(base, p) or fnmatch.fnmatch(relative, p) for p in patterns)

    return (wanted is None or hit(wanted)) and not hit(skipped)


def _supported(suffix: str) -> bool:
    return suffix in _CSV or suffix in _JSON or suffix in _EXCEL or suffix in _TEXT


def _local_sources(
    root: Path, max_bytes: int, wanted: list[str] | None, skipped: list[str], result: FileScan
) -> Iterator[_Source]:
    if root.is_file():
        paths = [(root, root.name)]
    elif root.is_dir():
        paths = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                full = Path(dirpath) / filename
                paths.append((full, full.relative_to(root).as_posix()))
    else:
        raise FileNotFoundError(f"No such file or folder: {root}")
    for path, relative in paths:
        suffix = path.suffix.lower()
        if path.is_symlink() or not _supported(suffix) or not _matches(path.name, relative, wanted, skipped):
            result.files_skipped += 1
            continue
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                data = handle.read(max_bytes)
        except OSError as exc:
            result.errors.append(f"{relative}: {type(exc).__name__}")
            continue
        yield _Source(relative, suffix, data, truncated=size > max_bytes)


def _s3_sources(
    target: str, client: Any, max_bytes: int, wanted: list[str] | None, skipped: list[str], result: FileScan
) -> Iterator[_Source]:
    bucket, _, prefix = target[len("s3://") :].partition("/")
    if not bucket:
        raise ValueError("S3 target must look like s3://bucket/prefix")
    if client is None:
        try:
            import boto3  # type: ignore[import-not-found,import-untyped,unused-ignore]
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise ImportError("Scanning S3 needs boto3: pip install 'dpdpkit-pii[s3]'") from exc
        client = boto3.client("s3")
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key: str = obj["Key"]
            suffix = PurePosixPath(key).suffix.lower()
            relative = key[len(prefix) :].lstrip("/") or PurePosixPath(key).name
            if key.endswith("/") or not _supported(suffix) or not _matches(key, relative, wanted, skipped):
                result.files_skipped += 1
                continue
            name = f"s3://{bucket}/{key}"
            try:
                body = client.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{max_bytes - 1}")["Body"]
                data = body.read()
            except Exception as exc:
                result.errors.append(f"{name}: {type(exc).__name__}")
                continue
            yield _Source(name, suffix, data, truncated=int(obj.get("Size", 0)) > max_bytes)


def _scan_source(
    source: _Source, sample: int, text_lines: int, recognizers: Sequence[PatternRecognizer]
) -> list[FileFinding]:
    suffix = source.suffix
    if suffix in _CSV:
        text = source.data.decode("utf-8-sig", errors="replace")
        rows = csv.reader(io.StringIO(text, newline=""), delimiter=_CSV[suffix])
        header = next(rows, [])
        return _scan_table(source.name, "", header, rows, sample, recognizers)
    if suffix in _JSON:
        if source.truncated:
            raise ValueError("file too large for JSON")
        return _scan_json(source, sample, recognizers)
    if suffix in _EXCEL:
        if source.truncated:
            raise ValueError("file too large for Excel")
        return _scan_excel(source, sample, recognizers)
    return _scan_text(source, text_lines, recognizers)


def _scan_table(
    file: str,
    prefix: str,
    header: Sequence[object],
    rows: Iterable[Sequence[object]],
    sample: int,
    recognizers: Sequence[PatternRecognizer],
) -> list[FileFinding]:
    names = [str(h).strip() if h is not None and str(h).strip() else f"column {i + 1}" for i, h in enumerate(header)]
    values: list[list[object]] = [[] for _ in names]
    for count, row in enumerate(rows):
        if count >= sample * _ROW_FACTOR:
            break
        for i, cell in enumerate(row[: len(names)]):
            if cell is not None and str(cell).strip() and len(values[i]) < sample:
                values[i].append(cell)
        if all(len(v) >= sample for v in values):
            break
    return [
        finding
        for name, column in zip(names, values, strict=True)
        if (finding := _finding(file, prefix + name, classify_column(name), column, recognizers)) is not None
    ]


def _finding(
    file: str,
    name: str,
    name_match: ColumnMatch | None,
    values: Iterable[object],
    recognizers: Sequence[PatternRecognizer],
) -> FileFinding | None:
    sampled, entities = _count_hits(values, recognizers)
    if name_match is None and not entities:
        return None
    return FileFinding(file, name, sampled, entities, name_match, _confidence(name_match, sampled, entities))


def _scan_excel(source: _Source, sample: int, recognizers: Sequence[PatternRecognizer]) -> list[FileFinding]:
    try:
        from openpyxl import load_workbook  # type: ignore[import-untyped,unused-ignore]
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError("Scanning Excel files needs openpyxl: pip install 'dpdpkit-pii[excel]'") from exc
    workbook = load_workbook(io.BytesIO(source.data), read_only=True, data_only=True)
    findings: list[FileFinding] = []
    try:
        for sheet in workbook.worksheets:
            rows = sheet.iter_rows(values_only=True)
            header = next(rows, ())
            findings.extend(_scan_table(source.name, f"{sheet.title}/", header, rows, sample, recognizers))
    finally:
        workbook.close()
    return findings


def _scan_json(source: _Source, sample: int, recognizers: Sequence[PatternRecognizer]) -> list[FileFinding]:
    text = source.data.decode("utf-8-sig", errors="replace")
    if source.suffix == ".json":
        documents = [json.loads(text)]
    else:
        documents = [json.loads(line) for line in text.splitlines() if line.strip()]
    values: dict[str, list[object]] = {}
    for document in documents:
        stack: list[tuple[str, object]] = [("", document)]
        while stack:
            path, node = stack.pop()
            if isinstance(node, dict):
                stack.extend((f"{path}.{k}" if path else str(k), v) for k, v in node.items())
            elif isinstance(node, list):
                stack.extend((f"{path}[]", v) for v in node)
            elif node is not None and not isinstance(node, bool) and str(node).strip():
                bucket = values.setdefault(path or "(value)", [])
                if len(bucket) < sample:
                    bucket.append(node)
    findings = []
    for path in sorted(values):
        key = path.rsplit(".", 1)[-1].removesuffix("[]")
        if (f := _finding(source.name, path, classify_column(key), values[path], recognizers)) is not None:
            findings.append(f)
    return findings


def _scan_text(source: _Source, text_lines: int, recognizers: Sequence[PatternRecognizer]) -> list[FileFinding]:
    text = source.data.decode("utf-8", errors="replace")
    lines = (line for line in text.splitlines() if line.strip())
    sampled, entities = _count_hits((line for _, line in zip(range(text_lines), lines, strict=False)), recognizers)
    if not entities:
        return []
    return [FileFinding(source.name, "(text)", sampled, entities, None, _TEXT_CONFIDENCE)]
