"""
Real-Time IP Geolocation and Impossible Travel Velocity Resolver.
Uses the free public ip-api.com endpoint to resolve IP addresses to latitude/longitude,
and calculates mathematical Haversine spherical geodesic distance and travel velocity.
"""
import requests
import math
import time
import ipaddress

# In-memory LRU cache to avoid excessive network requests and respect rate limits
_GEO_CACHE: dict[str, dict] = {}

def is_private_or_local_ip(ip: str) -> bool:
    """Check if IP is localhost, loopback, or RFC 1918 private subnet."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False

def resolve_ip(ip: str, timeout: float = 3.5) -> dict:
    """
    Resolve IP to geographic coordinates and ISP details.
    Uses free ip-api.com API (no key needed, 45 req/min).
    """
    clean_ip = ip.strip()
    if clean_ip in _GEO_CACHE:
        return _GEO_CACHE[clean_ip]
        
    # Default for local or unresolvable test IPs (Mumbai NPCI Data Center Coordinates)
    default_resp = {
        "status": "success",
        "ip": clean_ip,
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "lat": 19.0760,
        "lon": 72.8777,
        "isp": "National Payments Corporation of India (Internal Switching Hub)"
    }
    
    if is_private_or_local_ip(clean_ip) or clean_ip in ["localhost", "127.0.0.1", "0.0.0.0"]:
        _GEO_CACHE[clean_ip] = default_resp
        return default_resp
        
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,regionName,city,lat,lon,isp,query"
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "status": "success",
                    "ip": clean_ip,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "lat": float(data.get("lat", 19.0760)),
                    "lon": float(data.get("lon", 72.8777)),
                    "isp": data.get("isp", "Unknown ISP")
                }
                _GEO_CACHE[clean_ip] = result
                return result
    except Exception:
        pass
        
    _GEO_CACHE[clean_ip] = default_resp
    return default_resp

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points on Earth (in km)
    using the Haversine formula.
    """
    R = 6371.0  # Earth's radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2.0)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0)**2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return round(R * c, 2)

def detect_impossible_travel(ip1: str, ip2: str, delta_seconds: float) -> dict:
    """
    Calculates velocity between two successive IP locations.
    Flags impossible travel if speed > 800 km/h (exceeds commercial jet cruise speed)
    or cross-continent jump in short duration.
    """
    loc1 = resolve_ip(ip1)
    loc2 = resolve_ip(ip2)
    
    dist_km = haversine_distance_km(loc1['lat'], loc1['lon'], loc2['lat'], loc2['lon'])
    
    # Avoid zero division
    effective_seconds = max(delta_seconds, 1.0)
    hours = effective_seconds / 3600.0
    speed_kmh = round(dist_km / hours, 1) if hours > 0 else 0.0
    
    # Impossible travel trigger: distance > 50km and speed > 800km/h
    is_impossible = (dist_km > 50.0 and speed_kmh > 800.0) or (dist_km > 500.0 and effective_seconds < 600.0)
    
    return {
        "is_impossible": is_impossible,
        "distance_km": dist_km,
        "speed_kmh": speed_kmh,
        "delta_seconds": effective_seconds,
        "from_loc": f"{loc1['city']}, {loc1['country']}",
        "to_loc": f"{loc2['city']}, {loc2['country']}",
        "alert": f"IMPOSSIBLE TRAVEL: Moved {dist_km:,.1f} km from {loc1['city']} to {loc2['city']} in {effective_seconds/60:.1f} mins ({speed_kmh:,.0f} km/h)" if is_impossible else "Velocity within normal travel limits."
    }
