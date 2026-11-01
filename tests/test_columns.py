import pytest

from dpdpkit.pii import classify_column, classify_columns
from dpdpkit.pii.columns import column_words


@pytest.mark.parametrize(
    ("name", "category"),
    [
        ("aadhaar_no", "aadhaar"),
        ("AadhaarNumber", "aadhaar"),
        ("adhar", "aadhaar"),
        ("aadharno", "aadhaar"),
        ("pan_card", "pan"),
        ("PAN", "pan"),
        ("gstin", "gstin"),
        ("ifsc_code", "ifsc"),
        ("upi_id", "upi"),
        ("mobile", "mobile"),
        ("mobileNo", "mobile"),
        ("mobail_no", "mobile"),
        ("phone_number", "mobile"),
        ("contact_no", "mobile"),
        ("email_id", "email"),
        ("emailAddress", "email"),
        ("dob", "dob"),
        ("date_of_birth", "dob"),
        ("DateOfBirth", "dob"),
        ("janm_tithi", "dob"),
        ("janmtithi", "dob"),
        ("naam", "name"),
        ("first_name", "name"),
        ("poora_naam", "name"),
        ("pita_ka_naam", "relative_name"),
        ("father_name", "relative_name"),
        ("pata", "address"),
        ("ghar_ka_pata", "address"),
        ("home_address", "address"),
        ("pincode", "pincode"),
        ("voter_id", "voter_id"),
        ("passport_no", "passport"),
        ("vehicle_number", "vehicle"),
        ("abha_number", "abha"),
        ("bank_account_no", "bank_account"),
        ("khata_no", "bank_account"),
        ("users.mobile_no", "mobile"),
    ],
)
def test_matches(name: str, category: str) -> None:
    match = classify_column(name)
    assert match is not None
    assert match.category == category
    assert match.column == name


@pytest.mark.parametrize(
    "name",
    ["id", "created_at", "ip_address", "mac_address", "file_name", "table_name", "adobe", "metadata", "page", "total"],
)
def test_ignores(name: str) -> None:
    assert classify_column(name) is None


def test_entity_links_to_recognizer() -> None:
    assert classify_column("aadhaar_no").entity == "IN_AADHAAR"  # type: ignore[union-attr]
    assert classify_column("dob").entity is None  # type: ignore[union-attr]


def test_bare_name_is_weak() -> None:
    weak, strong = classify_column("name"), classify_column("full_name")
    assert weak is not None and strong is not None
    assert weak.confidence < strong.confidence


def test_words() -> None:
    assert column_words("db.Users.aadhaarNo2") == ("aadhaar", "no")
    assert column_words("") == ()


def test_classify_columns_keeps_order_and_drops_misses() -> None:
    result = classify_columns(["id", "mobile", "created_at", "dob"])
    assert [m.column for m in result] == ["mobile", "dob"]
