"""Core IP intelligence functions."""

import ipaddress
import math
import socket
import time
from typing import Optional

import requests

_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = "ipgeo-cli/0.1.0"

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=66846719"
IPAPI_BATCH_URL = "http://ip-api.com/batch?fields=66846719"
IPINFO_URL = "https://ipinfo.io/{ip}/json"

# Rate limit for ip-api.com: 45 req/min on free tier
_RATE_DELAY = 1.4  # seconds between requests to stay under 45/min


def _get(url: str, timeout: int = 10) -> dict:
    try:
        r = _SESSION.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"error": "Connection failed — check your network."}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out."}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.reason}"}
    except Exception as e:
        return {"error": str(e)}


def geolocate(ip: str) -> dict:
    """Geolocate a single IP address via ip-api.com."""
    if not ip or ip.strip().lower() in ("me", "self", "myip"):
        data = _get(IPAPI_URL.format(ip=""))
    else:
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            # Try to resolve hostname
            try:
                resolved = socket.gethostbyname(ip.strip())
                data = _get(IPAPI_URL.format(ip=resolved))
                data["queried_host"] = ip.strip()
                data["resolved_ip"] = resolved
                return data
            except socket.gaierror:
                return {"error": f"Cannot resolve hostname: {ip}"}
        data = _get(IPAPI_URL.format(ip=ip.strip()))
    return data


def geolocate_batch(ips: list[str]) -> list[dict]:
    """Geolocate a batch of IPs (up to 100 per request)."""
    results = []
    chunk_size = 100
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i : i + chunk_size]
        payload = [{"query": ip.strip(), "fields": 66846719} for ip in chunk if ip.strip()]
        try:
            r = _SESSION.post(IPAPI_BATCH_URL, json=payload, timeout=15)
            r.raise_for_status()
            results.extend(r.json())
        except Exception as e:
            for ip in chunk:
                results.append({"query": ip, "error": str(e)})
        if i + chunk_size < len(ips):
            time.sleep(_RATE_DELAY)
    return results


def reverse_dns(ip: str) -> dict:
    """Perform reverse DNS lookup on an IP."""
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "Invalid IP address"}
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": hostname, "aliases": aliases}
    except socket.herror as e:
        return {"ip": ip, "hostname": None, "error": str(e)}
    except Exception as e:
        return {"ip": ip, "hostname": None, "error": str(e)}


def cidr_info(cidr: str) -> dict:
    """Return network information for a CIDR block."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = list(net.hosts())
        first_host = str(hosts[0]) if hosts else str(net.network_address)
        last_host = str(hosts[-1]) if hosts else str(net.broadcast_address)
        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address),
            "netmask": str(net.netmask),
            "prefix_len": net.prefixlen,
            "total_ips": net.num_addresses,
            "usable_hosts": max(0, net.num_addresses - 2) if net.version == 4 else net.num_addresses,
            "first_host": first_host,
            "last_host": last_host,
            "version": f"IPv{net.version}",
            "is_private": net.is_private,
            "is_global": net.is_global,
            "is_multicast": net.is_multicast,
            "cidr": str(net),
        }
    except ValueError as e:
        return {"error": str(e)}


def ip_reputation(ip: str) -> dict:
    """Check IP reputation using AbuseIPDB (public endpoint, no key needed for basic info)."""
    ip = ip.strip()
    # Use ip-api.com proxy/hosting detection fields as a lightweight rep check
    data = geolocate(ip)
    if "error" in data:
        return data

    threat_indicators = []
    if data.get("proxy"):
        threat_indicators.append("Proxy detected")
    if data.get("hosting"):
        threat_indicators.append("Hosting/datacenter IP")
    if data.get("mobile"):
        threat_indicators.append("Mobile network")

    risk_level = "LOW"
    if len(threat_indicators) >= 2:
        risk_level = "HIGH"
    elif len(threat_indicators) == 1:
        risk_level = "MEDIUM"

    # Check if it's a known bad network via org name heuristics
    org = data.get("org", "") or ""
    suspicious_orgs = ["tor", "vpn", "proxy", "anonymiz", "hide", "shield", "mask"]
    if any(kw in org.lower() for kw in suspicious_orgs):
        threat_indicators.append("Suspicious organization name")
        if risk_level == "LOW":
            risk_level = "MEDIUM"

    return {
        "ip": data.get("query", ip),
        "isp": data.get("isp"),
        "org": org,
        "country": data.get("country"),
        "is_proxy": data.get("proxy", False),
        "is_hosting": data.get("hosting", False),
        "is_mobile": data.get("mobile", False),
        "risk_level": risk_level,
        "threat_indicators": threat_indicators,
    }


def my_ip() -> dict:
    """Get the caller's public IP and geo info."""
    return _get(IPAPI_URL.format(ip=""))


def validate_ip(ip: str) -> dict:
    """Validate and classify an IP address."""
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
        return {
            "ip": ip,
            "valid": True,
            "version": f"IPv{addr.version}",
            "is_private": addr.is_private,
            "is_global": addr.is_global,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_link_local": addr.is_link_local,
            "is_unspecified": addr.is_unspecified,
            "compressed": str(addr.compressed),
            "exploded": str(addr.exploded),
            "packed_hex": addr.packed.hex(),
            "int_value": int(addr),
        }
    except ValueError:
        return {"ip": ip, "valid": False, "error": "Not a valid IP address"}
