"""Find personal data in your databases and files: Indian PII recognizers (Aadhaar, PAN, GSTIN, UPI and more)
and a read-only scanner.

``india_recognizers()`` returns Presidio recognizers for the Indian identifiers, and ``classify_column()`` flags
column names (English and Hinglish) that look like personal data. The scanners are not built yet.
"""

from dpdpkit.pii.columns import ColumnMatch, classify_column, classify_columns
from dpdpkit.pii.recognizers import (
    AadhaarRecognizer,
    AbhaRecognizer,
    GstinRecognizer,
    IfscRecognizer,
    MobileRecognizer,
    PanRecognizer,
    PassportRecognizer,
    UpiRecognizer,
    VehicleRegistrationRecognizer,
    VoterIdRecognizer,
    india_recognizers,
)

__version__ = "0.0.1a0"

__all__ = [
    "AadhaarRecognizer",
    "AbhaRecognizer",
    "ColumnMatch",
    "GstinRecognizer",
    "IfscRecognizer",
    "MobileRecognizer",
    "PanRecognizer",
    "PassportRecognizer",
    "UpiRecognizer",
    "VehicleRegistrationRecognizer",
    "VoterIdRecognizer",
    "__version__",
    "classify_column",
    "classify_columns",
    "india_recognizers",
]
