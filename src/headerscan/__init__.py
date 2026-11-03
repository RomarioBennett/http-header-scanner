"""headerscan - grade a website's HTTP security headers."""

from .models import Finding, ScanResult, Severity, Status
from .scanner import ScanError, scan

__version__ = "1.0.0"
__all__ = [
    "Finding",
    "ScanError",
    "ScanResult",
    "Severity",
    "Status",
    "scan",
    "__version__",
]
