"""Column-name heuristics: flag columns likely to hold personal data from their names alone.

Names are split into lower-case words (``aadhaarNo``, ``Aadhaar_No`` and ``aadhaar-no`` all give ``aadhaar``,
``no``) and matched against English and common Hinglish spellings (``naam``, ``janm_tithi``, ``mobail``,
``adhar``). A match is a hint, not a finding: the name says nothing about the contents, so a name match is
reported with a confidence and callers should confirm it against sampled values.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")

STRONG = 0.9
WEAK = 0.5


@dataclass(frozen=True)
class ColumnMatch:
    """A column name that looks like personal data.

    ``category`` is a short label (``aadhaar``, ``dob``, ...). ``entity`` is the matching recognizer entity from
    :func:`dpdpkit.pii.india_recognizers`, or ``None`` where no recognizer exists (names, dates of birth).
    """

    column: str
    category: str
    entity: str | None
    confidence: float
    matched: str


@dataclass(frozen=True)
class _Rule:
    category: str
    entity: str | None
    words: tuple[tuple[str, ...], ...]  # contiguous word sequences
    compact: tuple[str, ...] = ()  # distinctive strings matched inside the name with separators removed
    confidence: float = STRONG
    exclude: frozenset[str] = frozenset()  # words that rule the rule out


def _w(*phrases: str) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(p.split()) for p in phrases)


_NOT_A_PERSON = frozenset("file table column schema host server company product brand city state country".split())

# Order matters: the first matching rule wins, so specific rules come before general ones.
_RULES: tuple[_Rule, ...] = (
    _Rule(
        "aadhaar",
        "IN_AADHAAR",
        _w("aadhaar", "aadhar", "adhar", "adhaar", "addhar", "aadhr", "uidai", "aadhaar no", "aadhaar num"),
        compact=("aadhaar", "aadhar", "adhaar", "adhar", "uidai"),
    ),
    _Rule("pan", "IN_PAN", _w("pan", "pan no", "pan num", "pan card", "pancard", "pan number", "permanent account")),
    _Rule("gstin", "IN_GSTIN", _w("gstin", "gst no", "gst number", "gst id"), compact=("gstin",)),
    _Rule("ifsc", "IN_IFSC", _w("ifsc", "ifsc code"), compact=("ifsc",)),
    _Rule("upi", "IN_UPI_ID", _w("upi", "upi id", "vpa"), compact=("upiid",)),
    _Rule("voter_id", "IN_VOTER", _w("voter id", "voter", "epic no", "matdata"), compact=("voterid",)),
    _Rule("passport", "IN_PASSPORT", _w("passport", "passport no", "passport num"), compact=("passport",)),
    _Rule(
        "vehicle",
        "IN_VEHICLE_REGISTRATION",
        _w("vehicle no", "vehicle number", "vehicle reg", "registration no", "rc no", "number plate", "gadi no"),
        compact=("vehicleno", "vehiclenumber", "numberplate"),
    ),
    _Rule("abha", "IN_ABHA", _w("abha", "abha no", "abha id", "abha address", "health id"), compact=("abha",)),
    _Rule(
        "driving_licence",
        None,
        _w("driving licence", "driving license", "dl no", "dl number", "licence no", "license no"),
        compact=("drivinglicen", "drivinglicense"),
    ),
    _Rule(
        "bank_account",
        None,
        _w("account no", "account number", "acct no", "bank account", "khata", "khata no", "khata number"),
        compact=("accountno", "accountnumber", "bankaccount", "acctno", "khatano"),
    ),
    _Rule(
        "email",
        None,
        _w("email", "e mail", "mail", "email id", "emailid", "email address"),
        compact=("email",),
    ),
    _Rule(
        "mobile",
        "IN_MOBILE",
        _w(
            "mobile",
            "mobail",
            "mob",
            "mob no",
            "phone",
            "phon",
            "phone no",
            "telephone",
            "telefon",
            "contact no",
            "contact number",
            "cell no",
            "whatsapp",
            "msisdn",
            "mobile no",
            "sampark",
            "sampark no",
        ),
        compact=("mobile", "mobail", "phoneno", "phonenumber", "contactno", "contactnumber", "whatsapp", "msisdn"),
    ),
    _Rule(
        "dob",
        None,
        _w(
            "dob",
            "birth date",
            "date of birth",
            "birthday",
            "birth day",
            "bday",
            "janm tithi",
            "janam tithi",
            "janm din",
            "janmdin",
            "janmatithi",
            "janmtithi",
            "janam din",
            "dt of birth",
            "d o b",
        ),
        compact=("dateofbirth", "birthdate", "janmtithi", "janamtithi", "janmdin", "janamdin", "birthday"),
    ),
    _Rule("age", None, _w("age", "umar", "umra", "aayu", "ayu"), confidence=WEAK),
    _Rule(
        "pincode",
        None,
        _w("pincode", "pin code", "pin", "postal code", "postcode", "zip", "zip code", "zipcode"),
        compact=("pincode", "postalcode", "zipcode"),
        confidence=WEAK,
    ),
    _Rule(
        "address",
        None,
        _w(
            "address",
            "addr",
            "pata",
            "pate",
            "ghar ka pata",
            "residence",
            "residential",
            "ghar",
            "street",
            "mohalla",
            "gaon",
            "village",
            "locality",
        ),
        compact=("address",),
        exclude=frozenset("ip mac url web wallet contract server host".split()),
    ),
    _Rule(
        "gender",
        None,
        _w("gender", "sex", "ling", "linga", "jaati ling", "lingam"),
        confidence=WEAK,
    ),
    _Rule("caste_religion", None, _w("caste", "jati", "jaati", "religion", "dharm", "dharam", "mazhab")),
    _Rule(
        "relative_name",
        None,
        _w(
            "father",
            "father name",
            "mother",
            "mother name",
            "spouse",
            "husband",
            "wife",
            "guardian",
            "pita",
            "pitaji",
            "pita ka naam",
            "mata",
            "mataji",
            "mata ka naam",
            "pati",
            "patni",
            "biwi",
            "shauhar",
            "nominee",
        ),
        compact=("fathername", "mothername", "spousename", "pitakanaam", "matakanaam"),
    ),
    _Rule(
        "name",
        None,
        _w(
            "first name",
            "last name",
            "full name",
            "middle name",
            "given name",
            "sur name",
            "surname",
            "family name",
            "customer name",
            "patient name",
            "applicant name",
            "employee name",
            "naam",
            "poora naam",
            "pura naam",
            "pehla naam",
            "aakhri naam",
            "nam",
            "fname",
            "lname",
            "fullname",
            "firstname",
            "lastname",
        ),
        compact=("firstname", "lastname", "fullname", "middlename", "surname", "naam"),
        exclude=_NOT_A_PERSON,
    ),
    _Rule("name", None, _w("name"), confidence=WEAK, exclude=_NOT_A_PERSON),
)


def column_words(name: str) -> tuple[str, ...]:
    """Split a column name into lower-case words. A qualified ``table.column`` name is reduced to the column."""
    leaf = name.rsplit(".", 1)[-1]
    parts = _NON_ALNUM.split(_CAMEL.sub("_", leaf))
    return tuple(p.lower() for p in parts if p and not p.isdigit())


def _contains(words: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    n = len(phrase)
    return any(words[i : i + n] == phrase for i in range(len(words) - n + 1))


def classify_column(name: str) -> ColumnMatch | None:
    """Return the personal-data category a column name suggests, or ``None``."""
    words = column_words(name)
    if not words:
        return None
    joined = "".join(words)
    for rule in _RULES:
        if rule.exclude.intersection(words):
            continue
        for phrase in rule.words:
            if _contains(words, phrase):
                return ColumnMatch(name, rule.category, rule.entity, rule.confidence, " ".join(phrase))
        for fragment in rule.compact:
            if fragment in joined:
                return ColumnMatch(name, rule.category, rule.entity, rule.confidence, fragment)
    return None


def classify_columns(names: Iterable[str]) -> list[ColumnMatch]:
    """Classify many column names, returning only those that look like personal data, in input order."""
    return [m for m in (classify_column(n) for n in names) if m is not None]
