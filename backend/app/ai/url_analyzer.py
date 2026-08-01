import re
from urllib.parse import urlparse

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "bankofamerica", "wellsfargo", "chase", "meta", "facebook", "instagram"
]
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly",
    "ow.ly", "tiny.cc", "goo.gl", "bit.do", "shorte.st"
]
SUSPICIOUS_TLDS = [".top", ".xyz", ".club", ".work", ".info", ".cn", ".tk", ".fit", ".icu", ".cam"]
EXECUTABLE_EXTENSIONS = [".exe", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".zip.exe", ".pdf.exe"]


class URLAnalyzer:
    @classmethod
    def analyze_single_url(cls, url: str) -> dict:
        """
        Analyzes a single URL across 6 distinct threat vectors.
        """
        if not url:
            return cls._empty_report(url)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        full_url = url.lower()

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

        # Vector 1: HTTPS Security Check
        is_https = (scheme == "https")
        if not is_https:
            vector_scores["https_score"] = 40
            reasons.append(f"Unencrypted HTTP protocol in use ('{scheme}://')")
            recommendations.append("Do NOT enter passwords or payment details on unencrypted HTTP web pages.")

        # Vector 2: Typosquatting & Brand Spoofing Check
        is_typosquatting = False
        spoofed_brand = None
        for brand in KNOWN_BRANDS:
            if brand in hostname:
                # If brand is inside hostname but hostname doesn't end with official domain
                if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") or hostname == f"{brand}.org" or hostname.endswith(f".{brand}.org")):
                    is_typosquatting = True
                    spoofed_brand = brand.capitalize()
                    vector_scores["typosquatting_score"] = 90
                    reasons.append(f"Domain '{hostname}' uses brand spoofing/typosquatting targeting {spoofed_brand}")
                    recommendations.append(f"Do NOT log in. This link is impersonating {spoofed_brand}.")
                    break

        # Vector 3: URL Shorteners Check
        is_shortened = any(shortener in hostname for shortener in SHORTENER_DOMAINS)
        if is_shortened:
            vector_scores["shortener_score"] = 65
            reasons.append(f"URL uses a link shortener service ('{hostname}') hiding the actual destination")
            recommendations.append("Use a URL expander service to reveal the true destination before clicking.")

        # Vector 4: Domain Length Check
        is_excessive_length = len(hostname) > 35
        if is_excessive_length:
            vector_scores["domain_length_score"] = 50
            reasons.append(f"Unnaturally long domain name ({len(hostname)} characters)")
            recommendations.append("Exercise caution; long obfuscated domains often conceal malicious hosts.")

        # Vector 5: Special Characters & Obfuscation Check
        has_at_symbol = "@" in full_url
        has_excessive_hyphens = hostname.count("-") >= 3
        has_excessive_subdomains = hostname.count(".") >= 4
        
        has_special_chars = has_at_symbol or has_excessive_hyphens or has_excessive_subdomains
        if has_at_symbol:
            vector_scores["special_chars_score"] = 95
            reasons.append("URL contains '@' symbol, a credential-harvesting redirection trick")
            recommendations.append("CRITICAL: Do NOT click. '@' symbols in URLs redirect browsers to fake destinations.")
        elif has_excessive_hyphens:
            vector_scores["special_chars_score"] = max(vector_scores["special_chars_score"], 45)
            reasons.append("Domain contains excessive hyphens used for visual spoofing")
        elif has_excessive_subdomains:
            vector_scores["special_chars_score"] = max(vector_scores["special_chars_score"], 40)
            reasons.append("Domain uses excessive subdomains to mimic trustworthy web addresses")

        # Vector 6: IP Address Hostname Check
        is_ip_address = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        if is_ip_address:
            vector_scores["ip_address_score"] = 85
            reasons.append(f"URL uses a raw IP address ('{hostname}') instead of a registered domain")
            recommendations.append("Legitimate services rarely use raw IP addresses in email links.")

        # Additional Check: Executable Download Extension
        has_executable = any(ext in path for ext in EXECUTABLE_EXTENSIONS)
        if has_executable:
            reasons.append(f"URL links directly to a dangerous executable or script file")
            recommendations.append("Do NOT download or execute files linked from unknown emails.")

        # Compute Unified URL Risk Score (0 - 100)
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
            "is_excessive_length": is_excessive_length,
            "has_special_chars": has_special_chars,
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
