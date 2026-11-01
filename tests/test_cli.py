import json

import pytest
import sqlalchemy as sa

from dpdpkit.pii.checksums import verhoeff_check_digit
from dpdpkit.pii.cli import main

AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
PAN = "ABCPE1234F"


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "kyc.csv").write_text("id,pan\n" + "".join(f"{i},{PAN}\n" for i in range(5)), encoding="utf-8")
    return tmp_path


def test_scans_folder_to_json_stdout(folder, capsys):
    assert main([str(folder)]) == 0  # markdown by default
    assert "kyc.csv:pan" in capsys.readouterr().out
    assert main([str(folder), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["unregistered"] == 1
    assert PAN not in json.dumps(data)


def test_out_format_from_suffix_and_overwrite(folder, tmp_path_factory, capsys):
    out = tmp_path_factory.mktemp("out") / "report.html"
    assert main([str(folder), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert main([str(folder), "--out", str(out)]) == 1
    assert "--overwrite" in capsys.readouterr().err
    assert main([str(folder), "--out", str(out), "--overwrite", "--format", "json"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["findings"] == 1


def test_registry_and_fail_on_gaps(folder, tmp_path_factory, capsys):
    reg = tmp_path_factory.mktemp("reg") / "registry.txt"
    reg.write_text("# registered\nkyc.csv:pan  # PAN\n\n", encoding="utf-8")
    assert main([str(folder), "--fail-on-gaps"]) == 2
    assert main([str(folder), "--fail-on-gaps", "--registry", str(reg)]) == 0
    assert main([str(folder), "--fail-on-gaps", "--registered", "kyc.csv:*"]) == 0
    capsys.readouterr()


def test_json_registry(folder, tmp_path_factory):
    reg = tmp_path_factory.mktemp("reg") / "registry.json"
    reg.write_text(json.dumps(["kyc.csv:pan"]), encoding="utf-8")
    assert main([str(folder), "--fail-on-gaps", "--registry", str(reg)]) == 0
    reg.write_text("[1]", encoding="utf-8")
    assert main([str(folder), "--registry", str(reg)]) == 1


def test_errors(folder, capsys):
    assert main([str(folder), "--sample", "0"]) == 1
    assert main([str(folder), "--registry", str(folder / "missing.txt")]) == 1
    assert capsys.readouterr().err.count("error:") == 2


def test_database_target_and_error_hides_url(tmp_path, capsys):
    path = tmp_path / "app.db"
    engine = sa.create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE customers (id INTEGER, pan TEXT)"))
        for i in range(5):
            conn.execute(sa.text("INSERT INTO customers VALUES (:i, :p)"), {"i": i, "p": PAN})
    engine.dispose()
    assert main([f"sqlite:///{path}", "--force", "--format", "json", "--registered", "customers.pan"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["name"].endswith("customers.pan") and data["findings"][0]["registered"]
    assert main(["nosuchdriver://user:secret@host/db"]) == 1
    assert "secret" not in capsys.readouterr().err


def test_registered_as_dpdpkit_subcommand():
    import argparse

    from dpdpkit.pii.cli import register

    parser = argparse.ArgumentParser()
    register(parser.add_subparsers(dest="command"))
    args = parser.parse_args(["scan", "somewhere", "--sample", "10"])
    assert args.sample == 10 and callable(args.func)
