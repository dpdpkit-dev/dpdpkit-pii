import io
import json

import pytest

from dpdpkit.pii import scan_files
from dpdpkit.pii.checksums import verhoeff_check_digit

AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
PAN = "ABCPE1234F"


def _by_name(scan):
    return {f.qualified_name: f for f in scan.findings}


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "customers.csv").write_text(
        "id,naam,notes,balance\n" + "".join(f"{i},Name {i},PAN {PAN},{i}\n" for i in range(1, 21)), encoding="utf-8"
    )
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "events.json").write_text(
        json.dumps({"users": [{"email": "a@b.in", "ref": AADHAAR, "n": 1} for _ in range(5)]}), encoding="utf-8"
    )
    (tmp_path / "sub" / "events.jsonl").write_text(json.dumps({"mobile": "9876543210"}) + "\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello\nmy pan is " + PAN + "\nbye\n", encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    return tmp_path


def test_scans_folder(folder):
    scan = scan_files(folder)
    found = _by_name(scan)
    assert found["customers.csv:notes"].entities == {"IN_PAN": 20}
    assert found["customers.csv:naam"].name_match is not None
    assert "customers.csv:balance" not in found
    assert found["sub/events.json:users[].ref"].entities == {"IN_AADHAAR": 5}
    assert "sub/events.json:users[].email" in found
    assert "sub/events.jsonl:mobile" in found
    assert found["notes.txt:(text)"].entities == {"IN_PAN": 1}
    assert "clean.txt:(text)" not in found
    assert scan.files_scanned == 5
    assert scan.files_skipped == 1
    assert scan.errors == []


def test_never_reports_values(folder):
    (folder / "bad.json").write_text('{"pan": "' + PAN + '"', encoding="utf-8")  # truncated JSON
    scan = scan_files(folder)
    dump = repr(scan)
    assert PAN not in dump
    assert AADHAAR not in dump
    assert scan.errors == ["bad.json: JSONDecodeError"]


def test_include_exclude_and_single_file(folder):
    only_csv = scan_files(folder, include=["*.csv"])
    assert {f.file for f in only_csv.findings} == {"customers.csv"}
    no_sub = scan_files(folder, exclude=["sub/*"])
    assert all(not f.file.startswith("sub/") for f in no_sub.findings)
    single = scan_files(folder / "notes.txt")
    assert single.files_scanned == 1


def test_missing_target(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_files(tmp_path / "nope")


def test_sample_validation(tmp_path):
    with pytest.raises(ValueError):
        scan_files(tmp_path, sample=0)


def test_sample_caps_values(tmp_path):
    (tmp_path / "a.csv").write_text("pan\n" + f"{PAN}\n" * 50, encoding="utf-8")
    scan = scan_files(tmp_path, sample=7)
    assert scan.findings[0].sampled == 7


def test_large_json_skipped_but_csv_truncated(tmp_path):
    (tmp_path / "big.json").write_text(json.dumps({"pan": [PAN] * 100}), encoding="utf-8")
    (tmp_path / "big.csv").write_text("pan\n" + f"{PAN}\n" * 100, encoding="utf-8")
    scan = scan_files(tmp_path, max_bytes=100)
    assert scan.errors == ["big.json: ValueError"]
    assert [f.file for f in scan.findings] == ["big.csv"]


def test_symlinks_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(PAN, encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link.txt").symlink_to(outside / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    scan = scan_files(root)
    assert scan.findings == []
    assert scan.files_skipped == 1


def test_excel(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "People"
    ws.append(["name", "pan_ref"])
    for i in range(5):
        ws.append([f"n{i}", PAN])
    wb.save(tmp_path / "people.xlsx")
    found = _by_name(scan_files(tmp_path))
    assert found["people.xlsx:People/pan_ref"].entities == {"IN_PAN": 5}


class _FakeS3:
    def __init__(self, objects):
        self.objects = objects

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        client = self

        class _Paginator:
            def paginate(self, Bucket, Prefix):
                keys = [k for k in client.objects if k.startswith(Prefix)]
                yield {"Contents": [{"Key": k, "Size": len(client.objects[k])} for k in keys]}

        return _Paginator()

    def get_object(self, Bucket, Key, Range):
        end = int(Range.split("-")[1])
        return {"Body": io.BytesIO(self.objects[Key][: end + 1])}


def test_s3_prefix():
    client = _FakeS3(
        {
            "data/a.csv": f"pan\n{PAN}\n".encode(),
            "data/dir/": b"",
            "data/pic.png": b"x",
            "other/b.csv": f"pan\n{PAN}\n".encode(),
        }
    )
    scan = scan_files("s3://bucket/data/", s3_client=client)
    assert [f.qualified_name for f in scan.findings] == ["s3://bucket/data/a.csv:pan"]
    assert scan.files_scanned == 1
    assert scan.files_skipped == 2


def test_s3_bad_target():
    with pytest.raises(ValueError):
        scan_files("s3:///x", s3_client=object())
