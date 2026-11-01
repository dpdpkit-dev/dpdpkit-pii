"""Find personal data in your databases and files: Indian PII recognizers (Aadhaar, PAN, GSTIN, UPI and more)
and a read-only scanner.

``india_recognizers()`` returns Presidio recognizers for the Indian identifiers. The scanners are not built yet.
"""

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
    "GstinRecognizer",
    "IfscRecognizer",
    "MobileRecognizer",
    "PanRecognizer",
    "PassportRecognizer",
    "UpiRecognizer",
    "VehicleRegistrationRecognizer",
    "VoterIdRecognizer",
    "__version__",
    "india_recognizers",
]
