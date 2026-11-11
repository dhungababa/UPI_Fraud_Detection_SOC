"""
Stateful Sliding-Window UPI Feature Store.
Maintains real-time velocity (10-minute burst, 1-hour rolling count & volume),
IP geolocations, and impossible travel detection per Payer VPA.
Thread-safe for production async/concurrent switch ingestion.
"""
import time
import threading
from collections import deque
from src.geo_resolver import resolve_ip, haversine_distance_km, detect_impossible_travel

class PayerProfile:
    def __init__(self, vpa: str):
        self.vpa = vpa
        # Stores (timestamp, amount, ip, lat, lon)
        self.transactions = deque()
        self.last_seen_ip: str = "127.0.0.1"
        self.last_seen_lat: float = 19.0760
        self.last_seen_lon: float = 72.8777
        self.last_seen_time: float = time.time()

    def add_transaction(self, amount: float, ip: str, ts: float):
        self.transactions.append((ts, amount, ip))
        # Keep only last 24h
        cutoff = ts - 86400
        while self.transactions and self.transactions[0][0] < cutoff:
            self.transactions.popleft()

    def get_rolling_stats(self, current_ts: float):
        cutoff_1h = current_ts - 3600
        cutoff_10m = current_ts - 600
        
        count_1h = 0
        amt_1h = 0.0
        count_10m = 0
        
        for ts, amt, _ in self.transactions:
            if ts >= cutoff_1h:
                count_1h += 1
                amt_1h += amt
            if ts >= cutoff_10m:
                count_10m += 1
                
        return {
            "txn_count_1h": count_1h,
            "txn_amount_1h": round(amt_1h, 2),
            "txn_count_10m": count_10m
        }

class StatefulFeatureStore:
    def __init__(self):
        self._profiles: dict[str, PayerProfile] = {}
        self._lock = threading.Lock()

    def enrich_and_record(self, payer_vpa: str, amount: float, client_ip: str = "127.0.0.1", 
                          timestamp: float = None) -> dict:
        """
        Calculates real dynamic rolling features and detects velocity / IP drift
        for incoming UPI transaction, then updates the profile state.
        """
        now = timestamp if timestamp is not None else time.time()
        
        with self._lock:
            if payer_vpa not in self._profiles:
                self._profiles[payer_vpa] = PayerProfile(payer_vpa)
                is_first_seen = True
            else:
                is_first_seen = False
                
            prof = self._profiles[payer_vpa]
            
            # Resolve current IP
            geo_info = resolve_ip(client_ip)
            curr_lat = geo_info['lat']
            curr_lon = geo_info['lon']
            
            # Compute IP drift
            if is_first_seen:
                drift_km = 0.0
                impossible_travel = {
                    "is_impossible": False,
                    "distance_km": 0.0,
                    "speed_kmh": 0.0,
                    "alert": "Initial baseline IP recorded."
                }
            else:
                delta_s = max(now - prof.last_seen_time, 1.0)
                impossible_travel = detect_impossible_travel(prof.last_seen_ip, client_ip, delta_s)
                drift_km = impossible_travel['distance_km']
                
            # Get rolling statistics before adding current transaction
            stats = prof.get_rolling_stats(now)
            
            # Record current transaction
            prof.add_transaction(amount, client_ip, now)
            prof.last_seen_ip = client_ip
            prof.last_seen_lat = curr_lat
            prof.last_seen_lon = curr_lon
            prof.last_seen_time = now
            
            # Post-record dynamic stats (including current txn)
            eff_count_1h = stats['txn_count_1h'] + 1
            eff_amt_1h = stats['txn_amount_1h'] + amount
            eff_count_10m = stats['txn_count_10m'] + 1
            
            return {
                "payer_vpa": payer_vpa,
                "client_ip": client_ip,
                "city": geo_info['city'],
                "country": geo_info['country'],
                "isp": geo_info['isp'],
                "txn_count_1h": eff_count_1h,
                "txn_amount_1h": round(eff_amt_1h, 2),
                "txn_count_10m": eff_count_10m,
                "geo_drift_km": drift_km,
                "is_impossible_travel": impossible_travel['is_impossible'],
                "travel_speed_kmh": impossible_travel.get('speed_kmh', 0.0),
                "travel_alert": impossible_travel.get('alert', '')
            }

# Global singleton instance
GLOBAL_FEATURE_STORE = StatefulFeatureStore()
