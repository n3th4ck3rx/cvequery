from typing import Optional, Dict, Any, Union
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import time
import os
from pathlib import Path
import platform
from src.constants import (
    BASE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_LIMIT,
    HTTP_OK,
    HTTP_BAD_REQUEST,
    HTTP_NOT_FOUND,
    HTTP_TOO_MANY_REQUESTS
)
from src.utils import create_cache_key

# Cache configuration
def get_cache_dir() -> Path:
    """Returns the appropriate cache directory path based on the operating system."""
    tool_name = "cvequery"
    
    if platform.system() in ["Linux", "Darwin"]:  # Unix-like systems (Linux, macOS)
        cache_dir = Path.home() / ".cache" / tool_name
    elif platform.system() == "Windows":
        cache_dir = Path.home() / "AppData" / "Local" / tool_name
    else:
        raise NotImplementedError(f"Unsupported operating system: {platform.system()}")
    
    # Create the directory if it doesn't exist
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir

CACHE_DIR = get_cache_dir()
CACHE_DURATION = 24 * 60 * 60  # 24 hours in seconds

# Setup requests session with retries
retry_strategy = Retry(
    total=3,  # Total number of retries
    status_forcelist=[HTTP_TOO_MANY_REQUESTS, 500, 502, 503, 504],  # Status codes to retry on
    allowed_methods=["GET"],  # Only retry GET requests
    backoff_factor=1  # Exponential backoff factor (e.g., 1s, 2s, 4s)
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http_session = requests.Session()
http_session.mount("https://", adapter)
http_session.mount("http://", adapter)

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

def _get_from_cache(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve data from cache if valid."""
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    if os.path.exists(cache_file):
        try:
            # Check cache file age
            file_age = time.time() - os.path.getmtime(cache_file)
            if file_age < CACHE_DURATION:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            else:
                # Cache expired, remove it
                os.remove(cache_file)
        except (IOError, ValueError) as e:
            # Log error or handle corrupted cache file
            print(f"Cache read error for {cache_key}: {e}")
            if os.path.exists(cache_file): # Attempt to remove corrupted file
                try:
                    os.remove(cache_file)
                except OSError:
                    pass # Ignore if removal fails
    return None

def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save data to cache."""
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    except IOError as e:
        # Log error or handle cache write error
        print(f"Cache write error for {cache_key}: {e}")

def get_cve_data(cve_id: str) -> Dict[str, Any]:
    """Get data for a specific CVE ID."""
    cache_key = create_cache_key("cve", cve_id=cve_id)
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    rate_limiter.wait()
    url = f"{BASE_URL}/cve/{cve_id}"
    try:
        response = http_session.get(
            url,
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        _save_to_cache(cache_key, data)
        return data
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
    cache_key_args = {
        "product": product, "cpe23": cpe23, "is_kev": is_kev,
        "sort_by_epss": sort_by_epss, "start_date": start_date, "end_date": end_date,
        "skip": skip, "limit": limit, "severity": severity # Severity included in cache key
    }
    # Filter out None values before creating cache key
    cache_key_args = {k: v for k, v in cache_key_args.items() if v is not None}
    cache_key = create_cache_key("cves", **cache_key_args)
    
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    rate_limiter.wait()
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
    # Severity is not passed to API, filtered client-side

    try:
        response = http_session.get(
            f"{BASE_URL}/cves",
            params=params,
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        
        if not isinstance(data, dict) or "cves" not in data:
            err_data = {"error": "Invalid response format from API"}
            # Do not cache error responses of this type as they might be transient
            return err_data
            
        _save_to_cache(cache_key, data)
        return data
    except requests.RequestException as e:
        # Do not cache general request exceptions
        return {"error": f"API request failed: {str(e)}"}
    except ValueError as e:
        # Do not cache parse errors
        return {"error": f"Failed to parse response: {str(e)}"}

def get_cpe_data(product_cpe: str, skip: int = 0, limit: int = DEFAULT_LIMIT) -> Dict[str, Any]:
    """
    Fetch CPEs related to a specific product.
    
    Args:
        product_cpe: Product name (e.g., apache or nginx)
        skip: Number of results to skip (default: 0)
        limit: Maximum number of results to return (default: DEFAULT_LIMIT)
    """
    # product_cpe is expected to be a product name, not a full cpe23 string from CLI call path
    cache_key = create_cache_key("cpes", product_name=product_cpe, skip=skip, limit=limit) # Changed key to product_name
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data
        
    rate_limiter.wait()
    url = f"{BASE_URL}/cpes"
    headers = {"Accept": "application/json"}
    
    skip_val = 0 if skip is None else skip
    # limit_val is taken directly from the limit argument, which now defaults to DEFAULT_LIMIT
    
    # The API endpoint expects a 'product' parameter for product name lookup.
    # The if product_cpe.startswith('cpe23=') block was removed as it's unreachable.
    params = {
        "product": product_cpe,
        "skip": str(skip_val),
        "limit": str(limit), # Use the limit argument directly
        "count": "false" 
    }
    
    try:
        response = http_session.get(
            url,
            headers=headers,
            params=params,
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code == HTTP_NOT_FOUND:
            # Cache "not found" responses as they are valid API states
            not_found_data = {"error": "No CPEs found", "cpes": [], "total": 0}
            _save_to_cache(cache_key, not_found_data)
            return not_found_data
            
        response.raise_for_status()
        data = response.json()
        
        # Standardize response format before caching and returning
        if isinstance(data, dict):
            cpes = data.get("cpes", [])
            total = data.get("total", len(cpes))
            processed_data = {"cpes": cpes, "total": total}
        elif isinstance(data, list):
            # This handles the alternative API response where it directly returns a list of CPEs
            processed_data = {"cpes": data, "total": len(data)}
        else:
            # Do not cache invalid format, return error directly
            return {"error": "Invalid response format", "cpes": [], "total": 0}

        _save_to_cache(cache_key, processed_data)
        return processed_data
        
    except requests.RequestException as e:
        # Do not cache general request exceptions
        return {"error": f"API request failed: {str(e)}", "cpes": [], "total": 0}
    except ValueError as e: # JSONDecodeError is a subclass of ValueError
        # Do not cache parse errors
        return {"error": f"Failed to parse JSON response: {str(e)}", "cpes": [], "total": 0}

