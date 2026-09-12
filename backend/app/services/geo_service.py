import logging
from pathlib import Path
from typing import Optional, Dict, Any
import geoip2.database
from geoip2.errors import AddressNotFoundError
from app.core.config import BASE_DIR

logger = logging.getLogger("mailshield.geo")

class GeoService:
    """
    IP Geolocation and ASN lookup service using local GeoLite2 databases.
    """
    _city_reader = None
    _asn_reader = None

    @classmethod
    def get_city_reader(cls):
        if cls._city_reader is None:
            db_path = BASE_DIR / "data" / "geolite" / "GeoLite2-City.mmdb"
            if db_path.exists():
                try:
                    cls._city_reader = geoip2.database.Reader(str(db_path))
                except Exception as e:
                    logger.error(f"Failed to open GeoLite2-City.mmdb at {db_path}: {e}")
            else:
                logger.warning(f"GeoLite2-City.mmdb not found at {db_path}")
        return cls._city_reader

    @classmethod
    def get_asn_reader(cls):
        if cls._asn_reader is None:
            db_path = BASE_DIR / "data" / "geolite" / "GeoLite2-ASN.mmdb"
            if db_path.exists():
                try:
                    cls._asn_reader = geoip2.database.Reader(str(db_path))
                except Exception as e:
                    logger.error(f"Failed to open GeoLite2-ASN.mmdb at {db_path}: {e}")
            else:
                logger.warning(f"GeoLite2-ASN.mmdb not found at {db_path}")
        return cls._asn_reader

    @classmethod
    def lookup_ip(cls, ip: str, ip_classification: Optional[str] = None) -> Dict[str, Any]:
        """
        Looks up an IP address and returns details:
        Country, City, ISP/Org, ASN, Latitude, Longitude.
        Returns fallback values if lookup fails or if IP is private/local.
        """
        # If classification is known to be non-public, bypass GeoLite lookup
        if ip_classification and ip_classification != "public":
            return cls._get_local_fallback(ip, ip_classification)

        if not ip:
            return cls._get_unknown_fallback(ip)

        # Check if databases are available
        city_reader = cls.get_city_reader()
        asn_reader = cls.get_asn_reader()

        result = {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "latitude": None,
            "longitude": None,
        }

        # 1. Geolocation lookup (City + Country + Coordinates)
        if city_reader:
            try:
                city_resp = city_reader.city(ip)
                if city_resp.country and city_resp.country.name:
                    result["country"] = city_resp.country.name
                elif city_resp.registered_country and city_resp.registered_country.name:
                    result["country"] = city_resp.registered_country.name
                    
                if city_resp.city and city_resp.city.name:
                    result["city"] = city_resp.city.name
                    
                if city_resp.location:
                    result["latitude"] = city_resp.location.latitude
                    result["longitude"] = city_resp.location.longitude
            except AddressNotFoundError:
                logger.debug(f"IP {ip} not found in GeoLite2-City database")
            except Exception as e:
                logger.error(f"Error during GeoLite2-City lookup for {ip}: {e}")

        # 2. ASN & ISP lookup
        if asn_reader:
            try:
                asn_resp = asn_reader.asn(ip)
                if asn_resp.autonomous_system_number:
                    result["asn"] = f"AS{asn_resp.autonomous_system_number}"
                if asn_resp.autonomous_system_organization:
                    result["isp"] = asn_resp.autonomous_system_organization
            except AddressNotFoundError:
                logger.debug(f"IP {ip} not found in GeoLite2-ASN database")
            except Exception as e:
                logger.error(f"Error during GeoLite2-ASN lookup for {ip}: {e}")

        return result

    @classmethod
    def _get_local_fallback(cls, ip: str, classification: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "country": "Local Network",
            "city": "Local Network",
            "isp": f"Private Address ({classification})",
            "asn": "Private Range",
            "latitude": None,
            "longitude": None,
        }

    @classmethod
    def _get_unknown_fallback(cls, ip: Optional[str]) -> Dict[str, Any]:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "latitude": None,
            "longitude": None,
        }
