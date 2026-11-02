"""Find personal data in your databases and files: Indian PII recognizers (Aadhaar, PAN, GSTIN, UPI and more)
and a read-only scanner.

``india_recognizers()`` returns Presidio recognizers for the Indian identifiers, and ``classify_column()`` flags
column names (English and Hinglish) that look like personal data. ``scan_database()`` inspects a database over a
read-only connection and reports columns and counts, never values. ``scan_files()`` does the same for CSV, JSON,
Excel and text files in a folder or under an S3 prefix. ``build_report()`` compares either scan with your registered
personal data and writes JSON, Markdown or HTML, counts only.
"""

from dpdpkit.pii.columns import ColumnMatch, classify_column, classify_columns
from dpdpkit.pii.database import ColumnFinding, DatabaseScan, ReadOnlyError, scan_database
from dpdpkit.pii.files import FileFinding, FileScan, scan_files
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
from dpdpkit.pii.report import RegistryDiff, Report, ReportRow, build_report, diff_registry

__version__ = "0.1.0a2"

__all__ = [
    "AadhaarRecognizer",
    "AbhaRecognizer",
    "ColumnFinding",
    "ColumnMatch",
    "DatabaseScan",
    "FileFinding",
    "FileScan",
    "GstinRecognizer",
    "IfscRecognizer",
    "MobileRecognizer",
    "PanRecognizer",
    "PassportRecognizer",
    "ReadOnlyError",
    "RegistryDiff",
    "Report",
    "ReportRow",
    "UpiRecognizer",
    "VehicleRegistrationRecognizer",
    "VoterIdRecognizer",
    "__version__",
    "build_report",
    "classify_column",
    "classify_columns",
    "diff_registry",
    "india_recognizers",
    "scan_database",
    "scan_files",
]
