"""Read-only database scanner: inspect the schema with SQLAlchemy and sample a capped number of values per column.

The scan runs over a connection that is read-only: the scanner refuses credentials that can write (unless
``force=True``) and, where the database supports it, also puts the session in read-only mode. Sampled values are
checked in memory against the India recognizers and then dropped; a finding holds the column, the entity types and
*counts*, never a value, and error messages never include values.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import sqlalchemy as sa
from presidio_analyzer import PatternRecognizer
from sqlalchemy.engine import Connection, Engine

from dpdpkit.pii.columns import ColumnMatch, classify_column
from dpdpkit.pii.recognizers import india_recognizers

DEFAULT_SAMPLE = 500
LOW_CONFIDENCE = 0.5  # findings below this are listed separately in ``DatabaseScan.low_confidence``

_MIN_SCORE = 0.3  # recognizer score a value needs to count as a hit
_MAX_VALUE_CHARS = 1000  # longer values are truncated before matching, which bounds regex cost
_MIN_VALUE_RATIO = 0.05  # share of sampled values that must match before values alone make a finding
_WRITE_GRANT = re.compile(r"\b(ALL|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|INDEX|REFERENCES)\b", re.IGNORECASE)


class ReadOnlyError(RuntimeError):
    """The connection can write, or could not be shown to be read-only."""


@dataclass(frozen=True)
class ColumnFinding:
    """A column that looks like it holds personal data.

    ``entities`` maps a recognizer entity to the number of sampled values it matched. ``name_match`` is the
    column-name hint, if any. ``confidence`` is 0-1: a name hint confirmed by values is highest, a name hint the
    values do not confirm is halved, and values alone scale with the share of sampled values that matched.
    """

    table: str
    column: str
    schema: str | None
    type: str
    sampled: int
    entities: dict[str, int]
    name_match: ColumnMatch | None
    confidence: float

    @property
    def qualified_name(self) -> str:
        return ".".join(p for p in (self.schema, self.table, self.column) if p)


@dataclass
class DatabaseScan:
    """Result of a scan. Holds counts and column names only."""

    findings: list[ColumnFinding] = field(default_factory=list)
    tables_scanned: int = 0
    columns_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def confident(self) -> list[ColumnFinding]:
        return [f for f in self.findings if f.confidence >= LOW_CONFIDENCE]

    @property
    def low_confidence(self) -> list[ColumnFinding]:
        return [f for f in self.findings if f.confidence < LOW_CONFIDENCE]


def _enforce_read_only(conn: Connection, force: bool) -> None:
    """Refuse a connection that can write, then make the session read-only where the dialect allows it."""
    dialect = conn.dialect.name
    if dialect == "sqlite":
        conn.exec_driver_sql("PRAGMA query_only = ON")  # SQLite has no users; this is the enforcement
        return
    if dialect == "postgresql":
        writable = conn.execute(
            sa.text(
                "SELECT COALESCE(bool_or(has_table_privilege(current_user, "
                "quote_ident(schemaname) || '.' || quote_ident(tablename), 'INSERT,UPDATE,DELETE,TRUNCATE')), false) "
                "FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')"
            )
        ).scalar()
    elif dialect in ("mysql", "mariadb"):
        grants = [str(row[0]).split(" ON ", 1)[0] for row in conn.exec_driver_sql("SHOW GRANTS")]
        writable = any(_WRITE_GRANT.search(g) for g in grants)
    else:
        writable = None  # unknown dialect: cannot be shown to be read-only
    if writable is not False and not force:
        reason = "can write" if writable else "could not be verified as read-only"
        raise ReadOnlyError(
            f"The {dialect} connection {reason}. Connect as a user with SELECT only, or pass force=True."
        )
    if dialect == "postgresql":
        conn.exec_driver_sql("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")  # survives a rollback
    elif dialect in ("mysql", "mariadb"):
        conn.exec_driver_sql("SET SESSION TRANSACTION READ ONLY")


def _is_sampleable(column_type: sa.types.TypeEngine) -> bool:
    """Text, numbers (Aadhaar or mobile numbers are often stored as integers) and dates; never binary data."""
    return not isinstance(column_type, sa.types.LargeBinary | sa.types.NullType)


def _count_hits(values: Iterable[object], recognizers: Sequence[PatternRecognizer]) -> tuple[int, dict[str, int]]:
    """Return how many values were examined and, per entity, how many of them matched."""
    sampled = 0
    hits: dict[str, int] = {}
    for value in values:
        text = str(value)[:_MAX_VALUE_CHARS]
        sampled += 1
        for recognizer in recognizers:
            entity = recognizer.supported_entities[0]
            if any(r.score >= _MIN_SCORE for r in recognizer.analyze(text, [entity])):
                hits[entity] = hits.get(entity, 0) + 1
    return sampled, hits


def _confidence(name_match: ColumnMatch | None, sampled: int, entities: dict[str, int]) -> float:
    ratio = max(entities.values()) / sampled if entities and sampled else 0.0
    if name_match is not None:
        if ratio >= _MIN_VALUE_RATIO:
            return max(name_match.confidence, 0.95)
        # Names are only a hint. An empty column cannot confirm or refute one, so it keeps its confidence.
        return name_match.confidence if sampled == 0 else round(name_match.confidence / 2, 2)
    return round(0.5 + 0.5 * ratio, 2) if ratio >= _MIN_VALUE_RATIO else round(0.3 + ratio, 2)


def scan_database(
    target: str | Engine,
    *,
    sample: int = DEFAULT_SAMPLE,
    schema: str | None = None,
    include_tables: Iterable[str] | None = None,
    exclude_tables: Iterable[str] = (),
    force: bool = False,
    recognizers: Sequence[PatternRecognizer] | None = None,
) -> DatabaseScan:
    """Scan one schema of a database for personal data.

    ``target`` is a SQLAlchemy URL or an ``Engine``. At most ``sample`` non-null values are read per column.
    Views are not scanned. A column is reported if its name looks like personal data or if the sampled values
    match a recognizer. Nothing is written to the database, to disk or to logs.
    """
    if sample < 1:
        raise ValueError("sample must be at least 1")
    active = list(recognizers) if recognizers is not None else india_recognizers()
    wanted = set(include_tables) if include_tables is not None else None
    skipped = set(exclude_tables)

    engine = sa.create_engine(target) if isinstance(target, str) else target
    result = DatabaseScan()
    try:
        with engine.connect() as conn:
            _enforce_read_only(conn, force)
            inspector = sa.inspect(conn)
            for table in sorted(inspector.get_table_names(schema=schema)):
                if table in skipped or (wanted is not None and table not in wanted):
                    continue
                result.tables_scanned += 1
                for col in inspector.get_columns(table, schema=schema):
                    result.columns_scanned += 1
                    finding = _scan_column(conn, table, col, schema, sample, active, result)
                    if finding is not None:
                        result.findings.append(finding)
    finally:
        if isinstance(target, str):
            engine.dispose()
    return result


def _scan_column(
    conn: Connection,
    table: str,
    col: sa.engine.interfaces.ReflectedColumn,
    schema: str | None,
    sample: int,
    recognizers: Sequence[PatternRecognizer],
    result: DatabaseScan,
) -> ColumnFinding | None:
    name = col["name"]
    name_match = classify_column(name)
    sampled = 0
    entities: dict[str, int] = {}
    if _is_sampleable(col["type"]):
        ref: sa.ColumnClause[object] = sa.column(name)
        query = sa.select(ref).select_from(sa.table(table, schema=schema)).where(ref.is_not(None)).limit(sample)
        try:
            sampled, entities = _count_hits((row[0] for row in conn.execute(query)), recognizers)
        except sa.exc.SQLAlchemyError as exc:
            conn.rollback()  # a failed statement poisons the transaction on some databases
            # Only the exception class: driver messages can quote the offending row.
            result.errors.append(f"{table}.{name}: {type(exc).__name__}")
    if name_match is None and not entities:
        return None
    return ColumnFinding(
        table=table,
        column=name,
        schema=schema,
        type=str(col["type"]),
        sampled=sampled,
        entities=entities,
        name_match=name_match,
        confidence=_confidence(name_match, sampled, entities),
    )
