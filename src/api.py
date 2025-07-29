from typing import Optional, Dict, Any, Union, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import time
import os
from pathlib import Path
import platform
import concurrent.futures
import threading
from functools import partial
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
        # Use Windows Temp directory for cache data (easier for users to manage)
        local_app_data = os.environ.get('LOCALAPPDATA')
        if local_app_data:
            # Use LOCALAPPDATA\Temp for cache (most reliable)
            cache_dir = Path(local_app_data) / "Temp" / tool_name
        else:
            # Fallback to USERPROFILE + AppData\Local\Temp
            user_profile = os.environ.get('USERPROFILE')
            if user_profile:
                cache_dir = Path(user_profile) / "AppData" / "Local" / "Temp" / tool_name
            else:
                # Final fallback to system temp directory
                import tempfile
                cache_dir = Path(tempfile.gettempdir()) / tool_name
    else:
        raise NotImplementedError(f"Unsupported operating system: {platform.system()}")
    
    # Create the directory if it doesn't exist
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as e:
        # If we can't create the directory, fall back to a temp directory
        import tempfile
        cache_dir = Path(tempfile.gettempdir()) / tool_name
        cache_dir.mkdir(parents=True, exist_ok=True)
        print(f"Warning: Using temporary cache directory: {cache_dir}")
    
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

# Rate limiting temporarily disabled for better performance
# class RateLimiter:
#     def __init__(self, calls_per_second=20):
#         self.calls_per_second = calls_per_second
#         self.last_call = 0
#         self.lock = threading.Lock()

#     def wait(self):
#         with self.lock:
#             now = time.time()
#             time_passed = now - self.last_call
#             if time_passed < 1/self.calls_per_second:
#                 time.sleep(1/self.calls_per_second - time_passed)
#             self.last_call = time.time()

# rate_limiter = RateLimiter()

def _get_from_cache(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve data from cache if valid (simplified for performance)."""
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    try:
        if os.path.exists(cache_file):
            # Quick cache age check
            file_age = time.time() - os.path.getmtime(cache_file)
            if file_age < CACHE_DURATION:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            else:
                # Cache expired, remove it silently
                os.remove(cache_file)
    except (IOError, ValueError, OSError):
        # Silently handle cache errors for better performance
        pass
    return None

def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save data to cache (simplified for performance)."""
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f)  # No indentation for faster writes
    except (IOError, OSError):
        # Silently handle cache write errors for better performance
        pass

def get_cve_data(cve_id: str) -> Dict[str, Any]:
    """Get data for a specific CVE ID with direct lookup (no rate limiting)."""
    # Check cache first for performance
    cache_key = create_cache_key("cve", cve_id=cve_id)
    cached_data = _get_from_cache(cache_key)
    if cached_data:
        return cached_data

    # Direct API call without rate limiting for faster response
    url = f"{BASE_URL}/cve/{cve_id}"
    try:
        response = http_session.get(
            url,
            headers={
                "Accept": "application/json",
                "Connection": "keep-alive"
            },
            timeout=10  # Reduced timeout for faster response
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

    # Direct API call without rate limiting
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
            headers={
                "Accept": "application/json",
                "Connection": "keep-alive"
            },
            timeout=10  # Reduced timeout for faster responses
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
        
    # Direct API call without rate limiting
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


def get_multiple_cves_parallel(cve_ids: List[str], max_workers: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch multiple CVEs in parallel for better performance.
    
    Args:
        cve_ids: List of CVE IDs to fetch
        max_workers: Maximum number of parallel workers
        
    Returns:
        List of CVE data dictionaries
    """
    results = []
    
    def fetch_single_cve(cve_id: str) -> Dict[str, Any]:
        """Fetch a single CVE and return the data."""
        return get_cve_data(cve_id)
    
    # Use ThreadPoolExecutor for I/O bound operations
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_cve = {executor.submit(fetch_single_cve, cve_id): cve_id for cve_id in cve_ids}
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                data = future.result()
                results.append(data)
            except Exception as e:
                results.append({"error": f"Failed to fetch {cve_id}: {str(e)}"})
    
    return results


def get_session_for_thread():
    """Get a thread-local session for better performance in parallel requests."""
    if not hasattr(threading.current_thread(), 'session'):
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        threading.current_thread().session = session
    return threading.current_thread().session


def batch_cve_lookup(cve_ids: List[str], batch_size: int = 20) -> List[Dict[str, Any]]:
    """Process CVE lookups in batches for optimal performance."""
    all_results = []
    
    # Process in batches to avoid overwhelming the API
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        batch_results = get_multiple_cves_parallel(batch, max_workers=min(10, len(batch)))
        all_results.extend(batch_results)
        
        # No delay between batches for maximum performance
    
    return all_results

def parallel_cpe_search(products: List[str], max_workers: int = 5) -> Dict[str, Any]:
    """Search for CPEs in parallel."""
    all_cpes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_product = {executor.submit(get_cpe_data, product): product for product in products}
        
        for future in concurrent.futures.as_completed(future_to_product):
            product = future_to_product[future]
            try:
                result = future.result()
                if 'cpes' in result:
                    all_cpes.extend(result['cpes'])
            except Exception as e:
                print(f"Error fetching CPEs for {product}: {e}")
    
    return {"cpes": all_cpes, "total": len(all_cpes)}

def enhanced_cve_search(
    products: Optional[List[str]] = None,
    cpe23: Optional[str] = None,
    is_kev: bool = False,
    sort_by_epss: bool = False,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    skip: int = 0,
    limit: int = DEFAULT_LIMIT,
    severity: Optional[str] = None,
    parallel: bool = True
) -> Dict[str, Any]:
    """Enhanced CVE search with parallel processing capabilities."""
    
    if products and len(products) > 1 and parallel:
        # Use parallel processing for multiple products
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for product in products:
                future = executor.submit(
                    get_cves_data,
                    product=product,
                    cpe23=cpe23,
                    is_kev=is_kev,
                    sort_by_epss=sort_by_epss,
                    start_date=start_date,
                    end_date=end_date,
                    skip=skip,
                    limit=limit,
                    severity=severity
                )
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if 'cves' in result:
                        all_results.extend(result['cves'])
                except Exception as e:
                    print(f"Error in parallel search: {e}")
        
        return {"cves": all_results, "total": len(all_results)}
    else:
        # Single product or non-parallel search
        product = products[0] if products else None
        return get_cves_data(
            product=product,
            cpe23=cpe23,
            is_kev=is_kev,
            sort_by_epss=sort_by_epss,
            start_date=start_date,
            end_date=end_date,
            skip=skip,
            limit=limit,
            severity=severity
        )