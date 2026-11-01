"""Presidio recognizers for Indian personal identifiers.

Each recognizer is a ``PatternRecognizer``; where the identifier has a checksum or a closed set of valid prefixes
the match is validated, so a failing candidate is dropped instead of being reported with a low score.
"""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer

from dpdpkit.pii.checksums import gstin_valid, verhoeff_valid

_SEPARATORS = re.compile(r"[\s-]")

# GST state and union territory codes, plus 97 (other territory) and 99 (centre jurisdiction).
_GST_STATE_CODES = frozenset(f"{n:02d}" for n in range(1, 39)) | {"97", "99"}

# RTO state and union territory codes. DD and DN were merged into DD; both still appear on older plates.
_RTO_STATE_CODES = frozenset(
    "AN AP AR AS BR CG CH DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP MZ NL OD OR PB PY RJ SK TN TR TS UK UP"
    " WB".split()
)

# Common UPI handles (payment service providers). Restricting to known handles keeps UPI IDs apart from e-mail.
UPI_HANDLES = (
    "ybl ibl axl okaxis oksbi okhdfcbank okicici paytm apl upi sbi hdfcbank icici axisbank axisb pnb boi cnrb "
    "kotak yesbank idfcbank indus fbl federal rbl aubank ikwik airtel postbank jio freecharge pingpay waaxis "
    "wahdfcbank waicici wasbi abfspay slice jupiter fam"
).split()


class _ValidatedRecognizer(PatternRecognizer):
    """PatternRecognizer whose subclass supplies ``_is_valid``; invalid matches are discarded.

    With ``CHECKSUM`` set, a valid match is a proven one and gets the maximum score; otherwise it keeps the
    pattern's score, which context words can raise.
    """

    CHECKSUM = False

    def _is_valid(self, text: str) -> bool:
        raise NotImplementedError

    def validate_result(self, pattern_text: str) -> bool | None:
        if not self._is_valid(pattern_text):
            return False
        return True if self.CHECKSUM else None


def _init(
    self: PatternRecognizer, entity: str, patterns: list[Pattern], context: list[str], ignore_case: bool = False
) -> None:
    flags = re.DOTALL | re.MULTILINE | (re.IGNORECASE if ignore_case else 0)
    PatternRecognizer.__init__(
        self,
        supported_entity=entity,
        patterns=patterns,
        context=context,
        supported_language="en",
        global_regex_flags=flags,
    )


class AadhaarRecognizer(_ValidatedRecognizer):
    """Aadhaar: 12 digits, first digit 2-9, plain or in groups of four split by a space or hyphen, Verhoeff-valid."""

    ENTITY = "IN_AADHAAR"
    CHECKSUM = True

    def __init__(self) -> None:
        patterns = [Pattern("aadhaar", r"(?<![\d-])[2-9]\d{3}(?:[ -]?)\d{4}(?:[ -]?)\d{4}(?![\d-])", 0.3)]
        _init(self, self.ENTITY, patterns, ["aadhaar", "aadhar", "uidai", "uid", "आधार"])

    def _is_valid(self, text: str) -> bool:
        digits = _SEPARATORS.sub("", text)
        if len(digits) != 12 or digits == digits[::-1] or len(set(digits)) == 1:
            return False
        return verhoeff_valid(digits)


class PanRecognizer(_ValidatedRecognizer):
    """PAN: five letters, four digits, a letter; the fourth letter is the holder type."""

    ENTITY = "IN_PAN"

    def __init__(self) -> None:
        patterns = [Pattern("pan", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.4)]
        _init(self, self.ENTITY, patterns, ["pan", "permanent account number", "income tax", "itr"])

    def _is_valid(self, text: str) -> bool:
        return True


class GstinRecognizer(_ValidatedRecognizer):
    """GSTIN: state code, embedded PAN, entity number, ``Z``, check character."""

    ENTITY = "IN_GSTIN"
    CHECKSUM = True

    def __init__(self) -> None:
        patterns = [Pattern("gstin", r"\b\d{2}[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", 0.4)]
        _init(self, self.ENTITY, patterns, ["gstin", "gst", "gst no", "gst number", "tax invoice"])

    def _is_valid(self, text: str) -> bool:
        return text[:2] in _GST_STATE_CODES and gstin_valid(text)


class IfscRecognizer(_ValidatedRecognizer):
    """IFSC: four-letter bank code, a zero, six-character branch code."""

    ENTITY = "IN_IFSC"

    def __init__(self) -> None:
        patterns = [Pattern("ifsc", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.4)]
        _init(self, self.ENTITY, patterns, ["ifsc", "ifs code", "bank", "branch", "neft", "rtgs", "imps"])

    def _is_valid(self, text: str) -> bool:
        # Branch codes are mostly numeric; a purely alphabetic tail is almost always an ordinary word.
        return any(ch.isdigit() for ch in text[5:])


class UpiRecognizer(_ValidatedRecognizer):
    """UPI ID (virtual payment address): ``handle@psp`` where the PSP is a known UPI handle."""

    ENTITY = "IN_UPI_ID"

    def __init__(self) -> None:
        handles = "|".join(sorted(UPI_HANDLES, key=len, reverse=True))
        patterns = [Pattern("upi", rf"(?<![\w.@-])[\w.-]{{2,64}}@(?:{handles})\b(?!\.[A-Za-z])", 0.6)]
        context = ["upi", "vpa", "gpay", "phonepe", "paytm", "bhim", "pay to"]
        _init(self, self.ENTITY, patterns, context, ignore_case=True)

    def _is_valid(self, text: str) -> bool:
        return True


class MobileRecognizer(_ValidatedRecognizer):
    """Indian mobile number: ten digits starting 6-9, optionally with +91, 91 or 0 and a split after five digits."""

    ENTITY = "IN_MOBILE"

    def __init__(self) -> None:
        patterns = [Pattern("mobile", r"(?<![\d+])(?:(?:\+91|91|0)[ -]?)?[6-9]\d{4}[ -]?\d{5}(?![\d-])", 0.4)]
        _init(self, self.ENTITY, patterns, ["mobile", "phone", "mob", "contact", "whatsapp", "cell", "number"])

    def _is_valid(self, text: str) -> bool:
        digits = _SEPARATORS.sub("", text).lstrip("+")
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        return len(digits) == 10 and len(set(digits)) > 1


class VoterIdRecognizer(_ValidatedRecognizer):
    """Voter ID (EPIC): three letters followed by seven digits."""

    ENTITY = "IN_VOTER"

    def __init__(self) -> None:
        patterns = [Pattern("voter_id", r"\b[A-Z]{3}\d{7}\b", 0.3)]
        _init(self, self.ENTITY, patterns, ["voter", "epic", "election", "electoral", "voter id"])

    def _is_valid(self, text: str) -> bool:
        return True


class PassportRecognizer(_ValidatedRecognizer):
    """Indian passport number: a letter (not Q, X or Z), then seven digits, optionally split after the third."""

    ENTITY = "IN_PASSPORT"

    def __init__(self) -> None:
        patterns = [Pattern("passport", r"\b[A-PR-WY][1-9]\d[ ]?\d{4}[1-9]\b", 0.1)]
        _init(self, self.ENTITY, patterns, ["passport", "passport no", "passport number", "travel document"])

    def _is_valid(self, text: str) -> bool:
        return True


class VehicleRegistrationRecognizer(_ValidatedRecognizer):
    """Vehicle registration plate: state code, district number, series letters, four digits; also BH series."""

    ENTITY = "IN_VEHICLE_REGISTRATION"

    def __init__(self) -> None:
        patterns = [
            Pattern("plate", r"\b[A-Z]{2}[ -]?\d{1,2}[A-Z]?[ -]?[A-Z]{1,3}[ -]?\d{4}\b", 0.2),
            Pattern("plate_bh", r"\b\d{2}[ -]?BH[ -]?\d{4}[ -]?[A-HJ-NP-Z]{2}\b", 0.5),
        ]
        _init(self, self.ENTITY, patterns, ["vehicle", "registration", "rc", "plate", "number plate", "rto"])

    def _is_valid(self, text: str) -> bool:
        compact = _SEPARATORS.sub("", text)
        return compact[:2] in _RTO_STATE_CODES or compact[2:4] == "BH"


class AbhaRecognizer(_ValidatedRecognizer):
    """ABHA (Ayushman Bharat Health Account): 14-digit number, usually written ``NN-NNNN-NNNN-NNNN``, or an address."""

    ENTITY = "IN_ABHA"

    def __init__(self) -> None:
        patterns = [
            Pattern("abha_hyphenated", r"(?<![\d-])\d{2}-\d{4}-\d{4}-\d{4}(?![\d-])", 0.6),
            Pattern("abha_spaced", r"(?<![\d-])\d{2} \d{4} \d{4} \d{4}(?!\d)", 0.4),
            Pattern("abha_plain", r"(?<!\d)\d{14}(?!\d)", 0.05),
            Pattern("abha_address", r"(?<![\w.@-])[A-Za-z][\w.]{2,31}@(?:abdm|sbx)\b", 0.7),
        ]
        _init(self, self.ENTITY, patterns, ["abha", "abdm", "ayushman", "health id", "health account", "ndhm"])

    def _is_valid(self, text: str) -> bool:
        return True


def india_recognizers() -> list[PatternRecognizer]:
    """One instance of every India recognizer, ready for ``AnalyzerEngine(registry=...)`` or ``add_recognizer``."""
    return [
        AadhaarRecognizer(),
        PanRecognizer(),
        GstinRecognizer(),
        IfscRecognizer(),
        UpiRecognizer(),
        MobileRecognizer(),
        VoterIdRecognizer(),
        PassportRecognizer(),
        VehicleRegistrationRecognizer(),
        AbhaRecognizer(),
    ]
