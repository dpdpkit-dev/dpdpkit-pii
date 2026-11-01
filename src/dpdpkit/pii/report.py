"""Registry diff and reports: compare scan findings with the registered personal data, and write JSON, Markdown or
HTML.

A report holds column or field names, entity types, sampled counts and registered or not, never values, because
findings never carry any. The registry is any collection of names (``customers.phone``, ``public.customers.*``,
``kyc.csv:pan``); this module does not depend on ``dpdpkit-core``, so pass the names from your
``PersonalDataRegistry`` (for Django or SQLAlchemy models, ``table.column``).
"""

from __future__ import annotations

import fnmatch
import html
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from dpdpkit.pii.database import ColumnFinding, DatabaseScan
from dpdpkit.pii.files import FileFinding, FileScan

Finding = ColumnFinding | FileFinding
Scan = DatabaseScan | FileScan

_HEADERS = ("Name", "Detected", "Sampled", "Confidence", "Registered")


@dataclass(frozen=True)
class ReportRow:
    """One finding as it appears in a report."""

    name: str
    kind: str  # "column" or "field"
    entities: dict[str, int]
    sampled: int
    confidence: float
    category: str | None  # from the name heuristic, if any
    registered: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "entities": dict(self.entities),
            "sampled": self.sampled,
            "confidence": round(self.confidence, 2),
            "category": self.category,
            "registered": self.registered,
        }

    @property
    def detected(self) -> str:
        parts = [f"{entity} ({count})" for entity, count in sorted(self.entities.items())]
        if not parts and self.category:
            parts = [f"name: {self.category}"]
        return ", ".join(parts) or "-"


@dataclass
class RegistryDiff:
    """Findings split by whether the registry covers them.

    ``unregistered`` are the gaps: personal data found in the scan that nobody registered. ``registered`` are
    findings the registry covers. ``unmatched`` are registry entries that matched no finding (not found by the
    scan, or already removed).
    """

    registered: list[Finding] = field(default_factory=list)
    unregistered: list[Finding] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)


@dataclass
class Report:
    """Scan findings compared with a registry. Counts and names only."""

    rows: list[ReportRow]
    unmatched: list[str]
    errors: list[str]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "findings": [r.as_dict() for r in self.rows],
            "registry_unmatched": list(self.unmatched),
            "errors": list(self.errors),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        lines = ["# Personal data scan", "", *(f"- {label}: {count}" for label, count in _summary_lines(self.summary))]
        lines += ["", "## Findings", ""]
        if self.rows:
            lines += ["| " + " | ".join(_HEADERS) + " |", "|" + " --- |" * len(_HEADERS)]
            lines += ["| " + " | ".join(_md(c) for c in _cells(r)) + " |" for r in self.rows]
        else:
            lines.append("No personal data found.")
        lines += self._md_list("Registered but not found in the scan", self.unmatched)
        lines += self._md_list("Errors", self.errors)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _md_list(title: str, items: list[str]) -> list[str]:
        return ["", f"## {title}", "", *(f"- {_md(i)}" for i in items)] if items else []

    def to_html(self) -> str:
        e = html.escape
        body = ["<h1>Personal data scan</h1>", "<ul>"]
        body += [f"<li>{e(label)}: {count}</li>" for label, count in _summary_lines(self.summary)]
        body += ["</ul>", "<h2>Findings</h2>"]
        if self.rows:
            body.append("<table>")
            body.append("<tr>" + "".join(f"<th>{e(h)}</th>" for h in _HEADERS) + "</tr>")
            for row in self.rows:
                css = "" if row.registered else ' class="gap"'
                body.append(f"<tr{css}>" + "".join(f"<td>{e(c)}</td>" for c in _cells(row)) + "</tr>")
            body.append("</table>")
        else:
            body.append("<p>No personal data found.</p>")
        for title, items in (("Registered but not found in the scan", self.unmatched), ("Errors", self.errors)):
            if items:
                body += [f"<h2>{e(title)}</h2>", "<ul>", *(f"<li>{e(i)}</li>" for i in items), "</ul>"]
        style = (
            "body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse}"
            "th,td{border:1px solid #bbb;padding:.3rem .6rem;text-align:left}tr.gap td{background:#fde8e8}"
        )
        return (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Personal data scan</title>\n'
            f"<style>{style}</style>\n</head>\n<body>\n" + "\n".join(body) + "\n</body>\n</html>\n"
        )

    def render(self, format: str) -> str:
        """Render as ``"json"``, ``"markdown"`` (or ``"md"``) or ``"html"``."""
        renderers = {"json": self.to_json, "markdown": self.to_markdown, "md": self.to_markdown, "html": self.to_html}
        try:
            return renderers[format.lower()]()
        except KeyError:
            raise ValueError(f"Unknown report format {format!r}; use json, markdown or html") from None


def _summary_lines(summary: dict[str, int]) -> list[tuple[str, int]]:
    labels = {
        "findings": "Findings",
        "registered": "Registered",
        "unregistered": "Not registered (gaps)",
        "registry_unmatched": "Registry entries not found in the scan",
        "errors": "Errors",
    }
    return [(labels[k], summary[k]) for k in labels if k in summary]


def _cells(row: ReportRow) -> list[str]:
    return [row.name, row.detected, str(row.sampled), f"{row.confidence:.2f}", "yes" if row.registered else "NO"]


def _md(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _patterns(registry: Iterable[str]) -> list[str]:
    return [p.strip().lower() for p in registry if p and p.strip()]


def _covers(pattern: str, finding: Finding) -> bool:
    """Exact (case-insensitive) or glob match; a database name may leave out the schema (``customers.pan``)."""
    name = finding.qualified_name.lower()
    if fnmatch.fnmatchcase(name, pattern):
        return True
    return isinstance(finding, ColumnFinding) and fnmatch.fnmatchcase(name, "*." + pattern)


def diff_registry(scan: Scan, registry: Iterable[str]) -> RegistryDiff:
    """Split the scan's findings into those the registry covers and those it does not.

    ``registry`` is a collection of names: ``table.column`` (or ``schema.table.column``) for databases,
    ``file:field`` for files, with ``*`` and ``?`` wildcards (``customers.*``). Matching ignores case.
    """
    patterns = _patterns(registry)
    used: set[str] = set()
    diff = RegistryDiff()
    for finding in scan.findings:
        hits = [p for p in patterns if _covers(p, finding)]
        used.update(hits)
        (diff.registered if hits else diff.unregistered).append(finding)
    diff.unmatched = sorted(set(patterns) - used)
    return diff


def build_report(scan: Scan, registry: Iterable[str] = ()) -> Report:
    """Compare a database or file scan with the registry and build a report.

    Rows list gaps first (unregistered), then registered findings, each by name. With an empty registry every
    finding counts as a gap.
    """
    diff = diff_registry(scan, registry)
    rows = [
        ReportRow(
            name=f.qualified_name,
            kind="column" if isinstance(f, ColumnFinding) else "field",
            entities=dict(f.entities),
            sampled=f.sampled,
            confidence=f.confidence,
            category=f.name_match.category if f.name_match else None,
            registered=registered,
        )
        for registered, group in ((False, diff.unregistered), (True, diff.registered))
        for f in sorted(group, key=lambda x: x.qualified_name)
    ]
    summary = {
        "findings": len(rows),
        "registered": len(diff.registered),
        "unregistered": len(diff.unregistered),
        "registry_unmatched": len(diff.unmatched),
        "errors": len(scan.errors),
    }
    return Report(rows, diff.unmatched, list(scan.errors), summary)
