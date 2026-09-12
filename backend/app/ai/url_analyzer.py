import re
from urllib.parse import urlparse

# Recognized official multi-domain infrastructures for trusted brands
BRAND_OFFICIAL_DOMAINS = {
    "google": [
        "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr",
        "google.org", "googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com",
        "gmail.com", "youtube.com", "youtu.be", "forms.gle", "withgoogle.com", "appspot.com",
        "1e100.net", "google.net", "googledrive.com", "googleblog.com"
    ],
    "microsoft": [
        "microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
        "outlook.com", "sharepoint.com", "msn.com", "azure.com", "windows.net", "bing.com",
        "visualstudio.com", "skype.com", "yammer.com", "linkedin.com", "licdn.com",
        "cloud.microsoft", "office.net", "microsoft.net", "msauth.net"
    ],
    "apple": [
        "apple.com", "icloud.com", "mzstatic.com", "me.com", "apple-dns.net"
    ],
    "amazon": [
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com",
        "media-amazon.com", "primevideo.com", "ssl-images-amazon.com"
    ],
    "paypal": [
        "paypal.com", "paypal.me", "paypal-community.com", "paypalobjects.com"
    ],
    "netflix": [
        "netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"
    ],
    "meta": [
        "facebook.com", "instagram.com", "meta.com", "whatsapp.com", "fb.com",
        "fbcdn.net", "cdninstagram.com", "threads.net"
    ],
    "facebook": [
        "facebook.com", "fb.com", "fbcdn.net"
    ],
    "instagram": [
        "instagram.com", "cdninstagram.com"
    ],
    "github": [
        "github.com", "github.io", "githubusercontent.com", "githubassets.com"
    ],
    "bankofamerica": [
        "bankofamerica.com", "bofa.com"
    ],
    "wellsfargo": [
        "wellsfargo.com"
    ],
    "chase": [
        "chase.com", "jpmorgan.com", "jpmorganchase.com"
    ]
}

SAFE_DOMAIN_SUFFIXES = [
    ".edu", ".ac.in", ".edu.in", ".nic.in", ".gov.in", ".gov", ".gov.uk",
    ".mil", ".int", "bmsit.in", "bmsit.ac.in", "kalantarart.org"
]

GENERIC_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly",
    "ow.ly", "tiny.cc", "goo.gl", "bit.do", "shorte.st"
]

SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".club", ".work", ".info", ".cn", ".tk", ".fit", ".icu",
    ".cam", ".click", ".gq", ".cf", ".ml", ".ga"
]

EXECUTABLE_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".zip.exe", ".pdf.exe", ".hta"
]


class URLAnalyzer:
    @classmethod
    def is_official_domain(cls, hostname: str, brand: str) -> bool:
        """
        Checks if hostname belongs to the official registered infrastructure for a given brand.
        """
        valid_domains = BRAND_OFFICIAL_DOMAINS.get(brand, [])
        for vd in valid_domains:
            if hostname == vd or hostname.endswith("." + vd):
                return True
        return False

    @classmethod
    def is_known_safe_infrastructure(cls, hostname: str) -> bool:
        """
        Checks if hostname is an established educational, governmental, or major tech domain.
        """
        if not hostname:
            return False
        # Academic & Gov domains
        for suffix in SAFE_DOMAIN_SUFFIXES:
            if hostname == suffix or hostname.endswith("." + suffix):
                return True
        # Major tech domains
        for brand, domains in BRAND_OFFICIAL_DOMAINS.items():
            for vd in domains:
                if hostname == vd or hostname.endswith("." + vd):
                    return True
        return False

    @classmethod
    def analyze_single_url(cls, url: str) -> dict:
        """
        Analyzes a single URL across distinct threat vectors.
        Benign URLs produce 0 risk score.
        """
        if not url:
            return cls._empty_report(url)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        reasons = []
        recommendations = []
        vector_scores = {
            "https_score": 0,
            "typosquatting_score": 0,
            "shortener_score": 0,
            "domain_length_score": 0,
            "special_chars_score": 0,
            "ip_address_score": 0
        }

        # Check if known safe/institutional infrastructure
        is_safe_infra = cls.is_known_safe_infrastructure(hostname)

        # Vector 1: HTTPS Check (Informational only — does not make a link malicious)
        is_https = (scheme == "https")
        if not is_https and not is_safe_infra:
            # Unencrypted HTTP on unknown external hosts is a mild hygiene concern, not automatic malware
            vector_scores["https_score"] = 15

        # Vector 2: Typosquatting & Brand Spoofing Check
        is_typosquatting = False
        spoofed_brand = None

        if not is_safe_infra:
            for brand, valid_domains in BRAND_OFFICIAL_DOMAINS.items():
                if brand in hostname:
                    if not cls.is_official_domain(hostname, brand):
                        # Detect deceptive patterns (e.g. paypal-security-login.com, login-google-auth.xyz, paypaI.com)
                        is_typosquatting = True
                        spoofed_brand = brand.capitalize()
                        vector_scores["typosquatting_score"] = 90
                        reasons.append(f"Domain '{hostname}' uses brand typosquatting/lookalike spoofing targeting {spoofed_brand}")
                        recommendations.append(f"Do NOT enter credentials on '{hostname}'. It is impersonating {spoofed_brand}.")
                        break

            # Check for suspicious TLDs on unknown domains
            if not is_typosquatting and any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
                vector_scores["domain_length_score"] = 35
                reasons.append(f"Domain uses high-abuse/suspicious top-level domain extension ('{hostname}')")

        # Vector 3: URL Shorteners Check (forms.gle is official Google forms; only check generic shorteners)
        is_shortened = any(hostname == shortener or hostname.endswith("." + shortener) for shortener in GENERIC_SHORTENERS)
        if is_shortened and not is_safe_infra:
            vector_scores["shortener_score"] = 20
            reasons.append(f"URL uses link shortener service ('{hostname}') concealing the destination")

        # Vector 4: Credential Harvesting '@' in Authority (RFC 3986 trick)
        # ONLY flag '@' if it occurs in netloc / authority (before host/port), NOT inside query parameters like ?Email=user@bmsit.in
        has_at_in_authority = "@" in netloc
        if has_at_in_authority:
            vector_scores["special_chars_score"] = 95
            reasons.append("URL contains '@' symbol in host authority, a credential-harvesting redirection exploit")
            recommendations.append("CRITICAL: Do NOT click. '@' symbols in URL authorities redirect to malicious destinations.")

        # Vector 5: Raw IP Address Destination
        is_ip_address = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        if is_ip_address:
            # Check for private vs public IP
            is_private_ip = hostname.startswith("10.") or hostname.startswith("192.168.") or hostname.startswith("172.16.")
            if not is_private_ip:
                vector_scores["ip_address_score"] = 85
                reasons.append(f"URL uses raw public IP address ('{hostname}') instead of a registered domain")
                recommendations.append("Avoid clicking raw IP address links from unknown senders.")

        # Vector 6: Direct Executable Download Extension in Path
        has_executable = any(path.endswith(ext) or ext in path for ext in EXECUTABLE_EXTENSIONS)
        if has_executable:
            reasons.append("URL links directly to a dangerous executable or script payload")
            recommendations.append("Do NOT download or run files linked in emails.")

        # Compute unified URL risk score (0 - 100)
        # If safe infrastructure and no executable/authority exploits -> score is 0
        if is_safe_infra and not has_at_in_authority and not has_executable:
            overall_score = 0
            reasons = []
        else:
            overall_score = max(
                vector_scores["https_score"],
                vector_scores["typosquatting_score"],
                vector_scores["shortener_score"],
                vector_scores["domain_length_score"],
                vector_scores["special_chars_score"],
                vector_scores["ip_address_score"],
                95 if has_executable else 0
            )

        if not recommendations:
            recommendations.append("URL appears clean. Standard browsing caution applies.")

        return {
            "url": url,
            "hostname": hostname,
            "scheme": scheme,
            "is_https": is_https,
            "is_typosquatting": is_typosquatting,
            "spoofed_brand": spoofed_brand,
            "is_shortened": is_shortened,
            "is_excessive_length": len(hostname) > 40,
            "has_special_chars": has_at_in_authority,
            "is_ip_address": is_ip_address,
            "has_executable": has_executable,
            "vector_scores": vector_scores,
            "risk_score": overall_score,
            "reasons": reasons,
            "recommendations": recommendations
        }

    @classmethod
    def analyze_urls(cls, urls: list[str]) -> tuple[int, list[dict], list[str], list[str]]:
        """
        Aggregates threat analysis across a list of URLs in an email.
        Returns: (Max Risk Score, list of URL reports, aggregated reasons, aggregated recommendations)
        """
        if not urls:
            return 0, [], [], []

        reports = []
        aggregated_reasons = []
        aggregated_recommendations = []
        max_score = 0

        for url in urls:
            report = cls.analyze_single_url(url)
            reports.append(report)
            max_score = max(max_score, report["risk_score"])

            for r in report["reasons"]:
                if r not in aggregated_reasons:
                    aggregated_reasons.append(r)
            for rec in report["recommendations"]:
                if rec not in aggregated_recommendations:
                    aggregated_recommendations.append(rec)

        return max_score, reports, aggregated_reasons, aggregated_recommendations

    @staticmethod
    def _empty_report(url: str) -> dict:
        return {
            "url": url,
            "hostname": "",
            "scheme": "",
            "is_https": False,
            "is_typosquatting": False,
            "spoofed_brand": None,
            "is_shortened": False,
            "is_excessive_length": False,
            "has_special_chars": False,
            "is_ip_address": False,
            "has_executable": False,
            "vector_scores": {
                "https_score": 0, "typosquatting_score": 0, "shortener_score": 0,
                "domain_length_score": 0, "special_chars_score": 0, "ip_address_score": 0
            },
            "risk_score": 0,
            "reasons": [],
            "recommendations": ["No URL provided."]
        }
