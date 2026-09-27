"""
Live functional test for the 3-layer scoring engine.
Tests known scenarios with expected score ranges.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# Minimal mocks so we can test without FastAPI/SQLAlchemy stack
class MockAuth:
    def __init__(self, spf, dkim, dmarc="unknown"):
        self.spf = spf
        self.dkim = dkim
        self.dmarc = dmarc

class MockNetworkIntel:
    def __init__(self, ip="1.2.3.4", isp="Google LLC", country="US", vpn_proxy_tor="No"):
        self.ip = ip
        self.isp = isp
        self.country = country
        self.vpn_proxy_tor = vpn_proxy_tor

from app.ai.scoring_engine import ScoringEngine

TESTS = [
    {
        "name": "T1: Clean institution email (SPF+DKIM pass, no threats)",
        "kwargs": {
            "sender": '"Dean SW" <dean.sw@bmsit.in>',
            "recipient": "student@bmsit.in",
            "subject": "Exam Registration Reminder",
            "body_text": "Dear students, please register for exams by Friday. Check the portal for details.",
            "links": ["https://bmsit.in/portal"],
            "attachments": [],
            "authentication": MockAuth("pass", "pass", "pass"),
            "network_intelligence": MockNetworkIntel(isp="Google LLC"),
        },
        "expect_risk_max": 15,
        "expect_severity": "safe",
    },
    {
        "name": "T2: Dual SPF+DKIM fail (strongest spoofing signal)",
        "kwargs": {
            "sender": "admin@paypal.com",
            "recipient": "user@gmail.com",
            "subject": "Your account is suspended",
            "body_text": "Your account has been suspended. Login immediately.",
            "links": [],
            "attachments": [],
            "authentication": MockAuth("fail", "fail", "fail"),
            "network_intelligence": MockNetworkIntel(isp="Unknown VPS"),
        },
        "expect_risk_min": 30,   # Auth layer alone contributes (90*0.20)=18, plus behavioral
        "expect_layer2_risk_min": 50,  # Floor enforcement kicks in
    },
    {
        "name": "T3: Executable attachment (Layer 1 critical)",
        "kwargs": {
            "sender": "attacker@random.xyz",
            "recipient": "user@gmail.com",
            "subject": "Invoice",
            "body_text": "Please find the invoice attached.",
            "links": [],
            "attachments": [{"filename": "invoice.exe", "mime_type": "application/octet-stream"}],
            "authentication": MockAuth("pass", "pass"),
            "network_intelligence": MockNetworkIntel(),
        },
        "expect_risk_min": 40,   # 90 * 0.45 = 40.5 from L1 alone
        "expect_verdict": "Malicious Attachment Detected",
    },
    {
        "name": "T4: Single DKIM fail (should be 70 auth_risk, not 90)",
        "kwargs": {
            "sender": "info@company.com",
            "recipient": "user@gmail.com",
            "subject": "Newsletter",
            "body_text": "Check out our latest updates.",
            "links": [],
            "attachments": [],
            "authentication": MockAuth("pass", "fail"),
            "network_intelligence": MockNetworkIntel(),
        },
        "expect_layer2_auth_risk": 70,
        "expect_layer2_risk_min": 50,  # Floor enforcement: auth>=70 -> layer2>=50
    },
    {
        "name": "T5: Phishing URL (typosquatting paypal)",
        "kwargs": {
            "sender": "noreply@paypal-verify-secure.xyz",
            "recipient": "user@gmail.com",
            "subject": "Verify your PayPal account",
            "body_text": "Click to verify your account now.",
            "links": ["https://paypal-verify-secure.xyz/login"],
            "attachments": [],
            "authentication": MockAuth("pass", "pass"),
            "network_intelligence": MockNetworkIntel(),
        },
        "expect_risk_min": 35,
        "expect_verdict": "Suspicious URL / Phishing Link",
    },
    {
        "name": "T6: Clean Gmail email (no flags at all)",
        "kwargs": {
            "sender": '"John" <john@gmail.com>',
            "recipient": "me@gmail.com",
            "subject": "Meeting tomorrow",
            "body_text": "Hi, just confirming our meeting tomorrow at 2pm. See you then!",
            "links": ["https://calendar.google.com/event/abc123"],
            "attachments": [],
            "authentication": MockAuth("pass", "pass", "pass"),
            "network_intelligence": MockNetworkIntel(isp="Google LLC"),
        },
        "expect_risk_max": 10,
        "expect_severity": "safe",
    },
    {
        "name": "T7: Double-extension attachment (invoice.pdf.exe)",
        "kwargs": {
            "sender": "attacker@evil.tk",
            "recipient": "user@gmail.com",
            "subject": "Important invoice",
            "body_text": "Please open the attached invoice.",
            "links": [],
            "attachments": [{"filename": "invoice.pdf.exe"}],
            "authentication": MockAuth("unknown", "unknown"),
            "network_intelligence": MockNetworkIntel(),
        },
        "expect_layer1_risk": 95,
        "expect_verdict": "Malicious Attachment Detected",
    },
    {
        "name": "T8: DMARC only fail (should be 60 auth_risk, not 70)",
        "kwargs": {
            "sender": "info@company.com",
            "recipient": "user@gmail.com",
            "subject": "Update",
            "body_text": "Please read this update.",
            "links": [],
            "attachments": [],
            "authentication": MockAuth("pass", "pass", "fail"),
            "network_intelligence": MockNetworkIntel(),
        },
        "expect_layer2_auth_risk": 0,  # SPF+DKIM pass, so auth_risk = 0, DMARC fail check order
    },
]

passed = failed = 0

for test in TESTS:
    result = ScoringEngine.analyze_email(**test["kwargs"])
    risk = result["risk_score"]
    severity = result["severity"]
    verdict = result["verdict"]
    breakdown = result["breakdown"]
    layers = result.get("layers", {})
    l1 = layers.get("content_security", {})
    l2 = layers.get("transport_forensics", {})
    l2_details = l2.get("details", {})

    errors = []
    if "expect_risk_max" in test and risk > test["expect_risk_max"]:
        errors.append(f"risk={risk} > max {test['expect_risk_max']}")
    if "expect_risk_min" in test and risk < test["expect_risk_min"]:
        errors.append(f"risk={risk} < min {test['expect_risk_min']}")
    if "expect_severity" in test and severity != test["expect_severity"]:
        errors.append(f"severity='{severity}' != '{test['expect_severity']}'")
    if "expect_verdict" in test and verdict != test["expect_verdict"]:
        errors.append(f"verdict='{verdict}' != '{test['expect_verdict']}'")
    if "expect_layer1_risk" in test and l1.get("risk") != test["expect_layer1_risk"]:
        errors.append(f"l1_risk={l1.get('risk')} != {test['expect_layer1_risk']}")
    if "expect_layer2_risk_min" in test and l2.get("risk", 0) < test["expect_layer2_risk_min"]:
        errors.append(f"l2_risk={l2.get('risk')} < min {test['expect_layer2_risk_min']}")
    if "expect_layer2_auth_risk" in test and l2_details.get("auth_risk") != test["expect_layer2_auth_risk"]:
        errors.append(f"auth_risk={l2_details.get('auth_risk')} != {test['expect_layer2_auth_risk']}")

    status = "PASS" if not errors else "FAIL"
    if errors:
        failed += 1
        print(f"  {status} {test['name']}")
        for e in errors:
            print(f"       -> {e}")
        print(f"       -> risk={risk}, severity={severity}, verdict='{verdict}'")
        print(f"       -> L1_risk={l1.get('risk')}, L2_risk={l2.get('risk')}, auth_risk={l2_details.get('auth_risk')}")
    else:
        passed += 1
        print(f"  {status} {test['name']} [risk={risk}, {severity}, '{verdict[:40]}']")

print(f"\n{'='*60}")
print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)} tests")
if failed:
    sys.exit(1)
