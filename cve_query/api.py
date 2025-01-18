import requests

BASE_URL = "https://cvedb.shodan.io"


def get_cve_data(cve_id):
    """Fetch details about a specific CVE."""
    url = f"{BASE_URL}/cve/{cve_id}"
    headers = {"Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return None


def get_cves_data(product=None, cpe23=None, is_kev=False, sort_by_epss=False,
                  start_date=None, end_date=None, skip=0, limit=100):
    """Fetch CVEs with various filters."""
    url = f"{BASE_URL}/cves"
    headers = {"Accept": "application/json"}
    params = {
        "product": product,
        "cpe23": cpe23,
        "is_kev": is_kev,
        "sort_by_epss": sort_by_epss,
        "start_date": start_date,
        "end_date": end_date,
        "skip": skip,
        "limit": limit
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CVEs data: {e}")
        return None


def get_cpe_data(product_cpe, skip=0, limit=100):
    """Fetch CPEs related to a specific product."""
    url = f"{BASE_URL}/cpes"
    headers = {"Accept": "application/json"}
    params = {"product": product_cpe, "skip": skip, "limit": limit}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CPE data: {e}")
        return None

