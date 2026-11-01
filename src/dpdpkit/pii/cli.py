"""``dpdpkit scan``: scan a database, folder, file or S3 prefix and write a report (names and counts, never values).

``dpdpkit-core`` loads :func:`register` through its ``dpdpkit.cli`` entry point, so ``dpdpkit scan`` exists once
``dpdpkit-pii`` is installed. :func:`main` runs the same command on its own (``python -m dpdpkit.pii``).

Exit status: 0 on success, 1 on a usage or scan error, 2 when ``--fail-on-gaps`` is set and the scan found personal
data the registry does not cover.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from dpdpkit.pii.database import DEFAULT_SAMPLE, scan_database
from dpdpkit.pii.files import DEFAULT_MAX_BYTES, DEFAULT_TEXT_LINES, scan_files
from dpdpkit.pii.report import Report, build_report

_SUFFIX_FORMATS = {".json": "json", ".md": "markdown", ".markdown": "markdown", ".html": "html", ".htm": "html"}
_FORMATS = ("json", "markdown", "html")


class CliError(Exception):
    """A problem to show the user as ``error: ...`` (exit status 1)."""


def _is_database(target: str) -> bool:
    return "://" in target and not target.lower().startswith("s3://")


def _read_registry(path: str | None, names: Sequence[str]) -> list[str]:
    """Names from ``--registry`` (a JSON array, or one per line with ``#`` comments) and ``--registered``."""
    out = list(names)
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError(f"cannot read registry file {path}: {type(exc).__name__}") from None
        if text.lstrip().startswith("["):
            try:
                loaded = json.loads(text)
            except ValueError:
                raise CliError(f"registry file {path} is not valid JSON") from None
            if not isinstance(loaded, list) or not all(isinstance(i, str) for i in loaded):
                raise CliError(f"registry file {path} must be a JSON array of strings")
            out += loaded
        else:
            out += [line.split("#", 1)[0].strip() for line in text.splitlines()]
    return [n for n in out if n]


def _format_for(args: argparse.Namespace) -> str:
    if args.format:
        return str(args.format)
    return _SUFFIX_FORMATS.get(Path(args.out).suffix.lower(), "markdown") if args.out else "markdown"


def _scan(args: argparse.Namespace) -> Any:
    target: str = args.target
    try:
        if _is_database(target):
            return scan_database(
                target,
                sample=args.sample,
                schema=args.schema,
                include_tables=args.include or None,
                exclude_tables=args.exclude,
                force=args.force,
            )
        return scan_files(
            target,
            sample=args.sample,
            include=args.include or None,
            exclude=args.exclude,
            max_bytes=args.max_bytes,
            text_lines=args.text_lines,
        )
    except ValueError as exc:
        raise CliError(str(exc)) from None
    except Exception as exc:
        # The class name only: driver and SDK messages can carry connection strings or row values.
        message = str(exc) if type(exc).__name__ == "ReadOnlyError" else type(exc).__name__
        raise CliError(f"scan failed: {message}") from None


def run(args: argparse.Namespace) -> int:
    try:
        if args.sample < 1:
            raise CliError("--sample must be at least 1")
        fmt = _format_for(args)
        registry = _read_registry(args.registry, args.registered)
        out = Path(args.out) if args.out else None
        if out and out.exists() and not args.overwrite:
            raise CliError(f"{out} already exists; pass --overwrite to replace it")
        report: Report = build_report(_scan(args), registry)
        text = report.render(fmt)
        if out:
            out.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {out} ({report.summary['findings']} findings)", file=sys.stderr)
        else:
            sys.stdout.write(text)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.fail_on_gaps and report.summary["unregistered"]:
        return 2
    return 0


def _add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", help="database URL (postgresql://...), folder, file, or s3://bucket/prefix")
    p.add_argument(
        "--sample", type=int, default=DEFAULT_SAMPLE, help=f"values to read per column (default {DEFAULT_SAMPLE})"
    )
    p.add_argument("--format", choices=_FORMATS, help="report format (default: from the --out suffix, else markdown)")
    p.add_argument("--out", help="write the report here instead of printing it")
    p.add_argument("--overwrite", action="store_true", help="replace --out if it exists")
    p.add_argument("--registry", metavar="FILE", help="registered names: a JSON array, or one per line")
    p.add_argument("--registered", action="append", default=[], metavar="NAME", help="a registered name (repeatable)")
    p.add_argument(
        "--include", action="append", default=[], metavar="PATTERN", help="tables (database) or globs (files)"
    )
    p.add_argument(
        "--exclude", action="append", default=[], metavar="PATTERN", help="tables (database) or globs (files)"
    )
    p.add_argument("--schema", help="database: schema to scan (default: the connection's default)")
    p.add_argument("--force", action="store_true", help="database: scan even if the connection can write")
    p.add_argument(
        "--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="files: read at most this many bytes per file"
    )
    p.add_argument("--text-lines", type=int, default=DEFAULT_TEXT_LINES, help="files: lines to read per text file")
    p.add_argument(
        "--fail-on-gaps", action="store_true", help="exit 2 if personal data is found that is not registered"
    )


def register(sub: Any) -> None:
    """Add ``scan`` to the ``dpdpkit`` CLI (``dpdpkit.cli`` entry point)."""
    p = sub.add_parser("scan", help="find personal data in a database, files or S3 (read-only; counts, never values)")
    _add_arguments(p)
    p.set_defaults(func=run)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dpdpkit scan", description="Find personal data; report names and counts only."
    )
    _add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
