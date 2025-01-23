# API Constants
BASE_URL = "https://cvedb.shodan.io"
DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 1000

# HTTP Status Codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429

# Severity Ranges
SEVERITY_MAP = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "none": (0.0, 0.0)
}

API_VERSION = "v1" 