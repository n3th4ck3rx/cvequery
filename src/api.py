from typing import Optional, Dict, Any, Union
import requests
import json
import time
from constants import (
    BASE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_LIMIT,
    HTTP_OK,
    HTTP_BAD_REQUEST,
    HTTP_NOT_FOUND,
    HTTP_TOO_MANY_REQUESTS
)
from utils import create_cache_key

class RateLimiter:
    def __init__(self, calls_per_second=2):
        self.calls_per_second = calls_per_second
        self.last_call = 0

    def wait(self):
        now = time.time()
        time_passed = now - self.last_call
        if time_passed < 1/self.calls_per_second:
            time.sleep(1/self.calls_per_second - time_passed)
        self.last_call = time.time()

rate_limiter = RateLimiter()

def get_cve_data(cve_id: str) -> Dict[str, Any]:
    """Get data for a specific CVE ID."""
    url = f"{BASE_URL}/cve/{cve_id}"
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": f"API request failed: {str(e)}"}

def get_cves_data(
    product: Optional[str] = None,
    cpe23: Optional[str] = None,
    is_kev: bool = False,
    sort_by_epss: bool = False,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    skip: int = 0,
    limit: int = DEFAULT_LIMIT,
    severity: Optional[str] = None
) -> Dict[str, Any]:
    """Get CVE data based on filters."""
    params = {}
    if product:
        params["product"] = product
    if cpe23:
        params["cpe23"] = cpe23
    if is_kev:
        params["is_kev"] = "true"
    if sort_by_epss:
        params["sort_by"] = "epss_score"
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
    if skip:
        params["skip"] = skip
    if limit:
        params["limit"] = limit
    if severity:
        params["severity"] = severity

    try:
        response = requests.get(
            f"{BASE_URL}/cves",
            params=params,
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        
        # Validate response structure
        if not isinstance(data, dict) or "cves" not in data:
            return {"error": "Invalid response format from API"}
            
        return data
    except requests.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except ValueError as e:
        return {"error": f"Failed to parse response: {str(e)}"}

def get_cpe_data(product_cpe: str, skip: int = 0, limit: int = 1000) -> Dict[str, Any]:
    """
    Fetch CPEs related to a specific product.
    
    Args:
        product_cpe: Product name or CPE 2.3 string
        skip: Number of results to skip (default: 0)
        limit: Maximum number of results to return (default: 1000)
    """
    url = f"{BASE_URL}/cpes"
    headers = {"Accept": "application/json"}
    
    # Ensure default values are used when None is passed
    skip_val = 0 if skip is None else skip
    limit_val = 1000 if limit is None else limit
    
    # Handle CPE 2.3 format
    if product_cpe.startswith('cpe23='):
        params = {
            "cpe23": product_cpe[6:],  # Remove 'cpe23=' prefix
            "skip": str(skip_val),
            "limit": str(limit_val),
            "count": "false"
        }
    else:
        params = {
            "product": product_cpe,
            "skip": str(skip_val),
            "limit": str(limit_val),
            "count": "false"
        }
    
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code == HTTP_NOT_FOUND:
            return {"error": "No CPEs found", "cpes": [], "total": 0}
            
        response.raise_for_status()
        data = response.json()
        
        # Handle total count properly
        if isinstance(data, dict):
            cpes = data.get("cpes", [])
            total = data.get("total", len(cpes))
            return {
                "cpes": cpes,
                "total": total
            }
        elif isinstance(data, list):
            return {
                "cpes": data,
                "total": len(data)
            }
        
        return {"error": "Invalid response format", "cpes": [], "total": 0}
        
    except requests.RequestException as e:
        error_msg = f"API request failed: {str(e)}"
        return {"error": error_msg, "cpes": [], "total": 0}

