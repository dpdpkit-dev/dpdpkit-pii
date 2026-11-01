import pytest
import sqlalchemy as sa

from dpdpkit.pii import ReadOnlyError, scan_database
from dpdpkit.pii.checksums import verhoeff_check_digit

AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
SECRET_PAN = "ABCPE1234F"


@pytest.fixture
def engine(tmp_path) -> sa.Engine:
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'app.db'}")
    with eng.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE customers (id INTEGER PRIMARY KEY, naam TEXT, notes TEXT, balance INTEGER)")
        conn.exec_driver_sql("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB, mobile TEXT)")
        conn.exec_driver_sql("CREATE TABLE empty_t (id INTEGER PRIMARY KEY, email TEXT)")
        rows = [(i, f"Name {i}", f"PAN {SECRET_PAN}" if i % 2 else "plain note", 100 + i) for i in range(1, 41)]
        conn.exec_driver_sql("INSERT INTO customers VALUES (?, ?, ?, ?)", rows)
        conn.exec_driver_sql("INSERT INTO blobs VALUES (1, x'0102', '9876543210')")
    return eng


def _by_name(scan):
    return {f.qualified_name: f for f in scan.findings}


def test_finds_by_name_and_by_value(engine):
    scan = scan_database(engine)
    found = _by_name(scan)
    assert found["customers.naam"].name_match.category == "name"
    notes = found["customers.notes"]
    assert notes.name_match is None
    assert notes.entities == {"IN_PAN": 20}
    assert notes.sampled == 40
    assert notes.confidence >= 0.5
    assert "customers.balance" not in found
    assert scan.tables_scanned == 3


def test_values_confirm_name_hint_and_unconfirmed_hint_is_low_confidence(engine):
    found = _by_name(scan_database(engine))
    assert found["blobs.mobile"].entities == {"IN_MOBILE": 1}
    assert found["blobs.mobile"].confidence >= 0.95
    assert found["customers.naam"].confidence < 0.5  # "Name 1" is not confirmed by any recognizer
    assert found["empty_t.email"].sampled == 0
    assert found["empty_t.email"].confidence == 0.9


def test_sample_is_capped(engine):
    notes = _by_name(scan_database(engine, sample=5))["customers.notes"]
    assert notes.sampled == 5


def test_integer_column_is_sampled(engine):
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE ids (v INTEGER)")
        conn.exec_driver_sql("INSERT INTO ids VALUES (?)", [(int(AADHAAR),)] * 3)
    assert _by_name(scan_database(engine, include_tables=["ids"]))["ids.v"].entities == {"IN_AADHAAR": 3}


def test_table_filters(engine):
    scan = scan_database(engine, include_tables=["customers", "blobs"], exclude_tables=["blobs"])
    assert scan.tables_scanned == 1
    assert {f.table for f in scan.findings} == {"customers"}


def test_report_never_contains_values(engine):
    scan = scan_database(engine)
    assert SECRET_PAN not in repr(scan)
    assert "9876543210" not in repr(scan)


def test_session_is_made_read_only(engine):
    from dpdpkit.pii import database

    with engine.connect() as conn:
        database._enforce_read_only(conn, force=False)
        with pytest.raises(sa.exc.OperationalError):
            conn.exec_driver_sql("INSERT INTO empty_t (id) VALUES (1)")


def test_column_error_reports_class_only(engine, monkeypatch):
    def boom(*_a, **_k):
        raise sa.exc.OperationalError("SELECT secret 9876543210", {}, Exception("row 9876543210"))

    monkeypatch.setattr("dpdpkit.pii.database._count_hits", boom)
    scan = scan_database(engine, include_tables=["empty_t"])
    assert sorted(scan.errors) == ["empty_t.email: OperationalError", "empty_t.id: OperationalError"]
    assert "9876543210" not in repr(scan)


def test_refuses_connection_that_cannot_be_shown_read_only():
    from dpdpkit.pii import database

    class FakeDialect:
        name = "oracle"

    class FakeConn:
        dialect = FakeDialect()

    with pytest.raises(ReadOnlyError):
        database._enforce_read_only(FakeConn(), force=False)  # type: ignore[arg-type]
    database._enforce_read_only(FakeConn(), force=True)  # type: ignore[arg-type]


def test_sample_must_be_positive(engine):
    with pytest.raises(ValueError):
        scan_database(engine, sample=0)


def test_url_target_is_disposed_and_scanned(tmp_path):
    path = tmp_path / "u.db"
    eng = sa.create_engine(f"sqlite:///{path}")
    with eng.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE t (pan TEXT)")
        conn.exec_driver_sql("INSERT INTO t VALUES (?)", [(SECRET_PAN,)])
    eng.dispose()
    scan = scan_database(f"sqlite:///{path}")
    assert scan.findings[0].entities == {"IN_PAN": 1}
