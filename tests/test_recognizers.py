import pytest
from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerRegistry

from dpdpkit.pii import india_recognizers
from dpdpkit.pii.checksums import gstin_check_char, gstin_valid, verhoeff_check_digit, verhoeff_valid


def _aadhaar(body: str = "23456789012") -> str:
    return body + verhoeff_check_digit(body)


def _gstin(body: str = "27AAPFU0939F1Z") -> str:
    return body + gstin_check_char(body)


@pytest.fixture(scope="module")
def engine() -> AnalyzerEngine:
    registry = RecognizerRegistry(supported_languages=["en"])
    for recognizer in india_recognizers():
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(registry=registry, supported_languages=["en"], nlp_engine=_NoNlp())


class _NoNlp:
    """Minimal NLP engine so tests need no spaCy model; pattern recognizers only need tokens for context."""

    def load(self) -> None: ...

    def is_loaded(self) -> bool:
        return True

    def get_supported_entities(self) -> list[str]:
        return []

    def get_supported_languages(self) -> list[str]:
        return ["en"]

    def process_text(self, text: str, language: str):  # type: ignore[no-untyped-def]
        from presidio_analyzer.nlp_engine import NlpArtifacts

        return NlpArtifacts([], [], [], [], None, language)  # type: ignore[arg-type]

    def process_batch(self, texts, language, **kwargs):  # type: ignore[no-untyped-def]
        for text in texts:
            yield text, self.process_text(text, language)


def _found(engine: AnalyzerEngine, text: str) -> dict[str, str]:
    return {r.entity_type: text[r.start : r.end] for r in engine.analyze(text=text, language="en")}


def test_verhoeff_known_vectors() -> None:
    assert verhoeff_valid("2363")  # classic example from the algorithm's description
    assert not verhoeff_valid("2364")
    assert not verhoeff_valid("")
    assert not verhoeff_valid("12a4")
    assert verhoeff_check_digit("236") == "3"


def test_gstin_checksum() -> None:
    assert gstin_valid(_gstin())
    bad = _gstin()[:-1] + ("0" if _gstin()[-1] != "0" else "1")
    assert not gstin_valid(bad)
    assert not gstin_valid("short")


def test_all_ten_entities_provided() -> None:
    entities = {e for r in india_recognizers() for e in r.supported_entities}
    assert entities == {
        "IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_IFSC", "IN_UPI_ID",
        "IN_MOBILE", "IN_VOTER", "IN_PASSPORT", "IN_VEHICLE_REGISTRATION", "IN_ABHA",
    }  # fmt: skip
    assert all(isinstance(r, EntityRecognizer) for r in india_recognizers())


@pytest.mark.parametrize("fmt", ["{0}", "{0[0]}{0[1]}{0[2]}{0[3]} {0[4]}{0[5]}{0[6]}{0[7]} {0[8]}{0[9]}{0[10]}{0[11]}"])
def test_aadhaar_plain_and_spaced(engine: AnalyzerEngine, fmt: str) -> None:
    number = _aadhaar()
    assert _found(engine, f"id {fmt.format(number)} end").get("IN_AADHAAR") == fmt.format(number)


def test_aadhaar_hyphenated(engine: AnalyzerEngine) -> None:
    n = _aadhaar()
    hyphenated = f"{n[:4]}-{n[4:8]}-{n[8:]}"
    assert _found(engine, f"Aadhaar: {hyphenated}")["IN_AADHAAR"] == hyphenated


def test_aadhaar_rejects_bad_checksum_and_leading_digit(engine: AnalyzerEngine) -> None:
    n = _aadhaar()
    wrong = n[:-1] + str((int(n[-1]) + 1) % 10)
    assert "IN_AADHAAR" not in _found(engine, f"x {wrong} y")
    assert "IN_AADHAAR" not in _found(engine, f"x {_aadhaar('13456789012')} y")


def test_pan(engine: AnalyzerEngine) -> None:
    assert _found(engine, "PAN ABCPE1234F")["IN_PAN"] == "ABCPE1234F"
    assert "IN_PAN" not in _found(engine, "ABCXE1234F")  # X is not a holder type


def test_gstin(engine: AnalyzerEngine) -> None:
    g = _gstin()
    assert _found(engine, f"GSTIN {g}")["IN_GSTIN"] == g
    assert "IN_GSTIN" not in _found(engine, f"GSTIN {g[:-1]}{'0' if g[-1] != '0' else '1'}")
    assert "IN_GSTIN" not in _found(engine, f"GSTIN {_gstin('85AAPFU0939F1Z')}")  # no such state code


def test_ifsc(engine: AnalyzerEngine) -> None:
    assert _found(engine, "IFSC SBIN0001234")["IN_IFSC"] == "SBIN0001234"
    assert "IN_IFSC" not in _found(engine, "word ABCD0ABCDEF")


def test_upi(engine: AnalyzerEngine) -> None:
    assert _found(engine, "pay to rahul.k@okaxis now")["IN_UPI_ID"] == "rahul.k@okaxis"
    assert "IN_UPI_ID" not in _found(engine, "mail rahul@example.com")


@pytest.mark.parametrize("number", ["9876543210", "98765 43210", "+91 98765 43210", "+91-9876543210", "09876543210"])
def test_mobile(engine: AnalyzerEngine, number: str) -> None:
    assert _found(engine, f"call {number} today")["IN_MOBILE"] == number


@pytest.mark.parametrize("text", ["5876543210", "9999999999", "98765432101"])
def test_mobile_rejects(engine: AnalyzerEngine, text: str) -> None:
    assert "IN_MOBILE" not in _found(engine, f"call {text} today")


def test_voter_id(engine: AnalyzerEngine) -> None:
    assert _found(engine, "voter id ABC1234567")["IN_VOTER"] == "ABC1234567"


def test_passport(engine: AnalyzerEngine) -> None:
    assert _found(engine, "passport no J8369854")["IN_PASSPORT"] == "J8369854"
    assert "IN_PASSPORT" not in _found(engine, "passport Z8369854")


def test_vehicle_registration(engine: AnalyzerEngine) -> None:
    assert _found(engine, "plate MH12AB1234")["IN_VEHICLE_REGISTRATION"] == "MH12AB1234"
    assert _found(engine, "plate DL-1C-AB-1234")["IN_VEHICLE_REGISTRATION"] == "DL-1C-AB-1234"
    assert _found(engine, "plate 22BH1234AA")["IN_VEHICLE_REGISTRATION"] == "22BH1234AA"
    assert "IN_VEHICLE_REGISTRATION" not in _found(engine, "plate ZZ12AB1234")


def test_abha(engine: AnalyzerEngine) -> None:
    assert _found(engine, "ABHA 91-1234-5678-9012")["IN_ABHA"] == "91-1234-5678-9012"
    assert _found(engine, "abha address priya.s@abdm")["IN_ABHA"] == "priya.s@abdm"
