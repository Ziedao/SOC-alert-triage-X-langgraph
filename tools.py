import os
import requests
import geoip2.database
from dotenv import load_dotenv
from langchain_core.tools import tool

# Load environment variables from the .env file
load_dotenv()

# Get the MaxMind database file from MaxMind's website
# You will need to download the GeoLite2-City.mmdb file and place it in your project folder
# This path should point to the downloaded file
# GEOLITE_DB_PATH = "GeoLite2-City.mmdb"

@tool
def get_virustotal_report(indicator: str, indicator_type: str = "ip"):
    """Searches VirusTotal for a report on an IP address, domain, or file hash.
    The indicator_type argument must be 'ip', 'domain', or 'hash'."""
    api_key = os.getenv("VT_API_KEY")
    headers = {"x-apikey": api_key}
    
    # Simple check to define the endpoint based on indicator type
    endpoint = ""
    if indicator_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif indicator_type == "hash":
        endpoint = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        return {"error": "Invalid indicator_type. Must be 'ip', 'domain', or 'hash'."}
    
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": data.get("malicious", 0),
            "harmless": data.get("harmless", 0),
            "suspicious": data.get("suspicious", 0)
        }
        #return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API call failed: {e}"}

@tool
def check_abuseipdb(ip_address: str):
    """Checks the reputation of an IP address using AbuseIPDB.
    Returns the abuse confidence score and the number of reports."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip_address}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "is_whitelisted": data.get("isWhitelisted")
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB API call failed: {e}"}

@tool
def get_geoip_location(ip_address: str):
    """Returns the geographic location of an IP address."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        if r.status_code != 200:
            return {"error": r.text}
        data = r.json()
        return {
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org")
        }
    except Exception as e:
        return {"error": f"GeoIP location retrieval failed: {e}"}

@tool
def check_vpn_proxy(ip_address: str):
    """Checks if an IP address is associated with a VPN, proxy, or TOR using ProxyCheck.io."""
    api_key = os.getenv("PROXYCHECK_API_KEY")  # put your free API key in .env
    url = f"https://proxycheck.io/v2/{ip_address}"
    params = {
        "key": api_key,        # your API key
        "vpn": 1,              # detect VPN
        "risk": 1,             # risk scoring
        "asn": 1,              # include ASN info
        "node": 1,             # detect TOR exit nodes
        "port": 1,             # check port status
        "days": 7              # history of IP activity
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if ip_address in data:
            ip_info = data[ip_address]
            return {
                "is_vpn": ip_info.get("vpn") == "yes",
                "is_proxy": ip_info.get("proxy") == "yes",
                "is_tor": ip_info.get("tor") == "yes",
                "risk_score": ip_info.get("risk"),
                "asn": ip_info.get("asn"),
                "organization": ip_info.get("isp"),
            }
        else:
            return {"error": "IP not found in ProxyCheck response"}
    except requests.exceptions.RequestException as e:
        return {"error": f"ProxyCheck API call failed: {e}"}
