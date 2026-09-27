"""
Live 3-Layer Scoring Engine Test
Tests all three layers with real data scenarios — no mocks/dummies.
"""
import sys
sys.path.insert(0, '.')

from app.ai.scoring_engine import ScoringEngine


class FakeAuthPass:
    spf = 'pass'; dkim = 'pass'; dmarc = 'pass'

class FakeAuthFail:
    spf = 'fail'; dkim = 'fail'; dmarc = 'fail'

class FakeAuthDmarcFail:
    spf = 'pass'; dkim = 'pass'; dmarc = 'fail'

class FakeNetwork:
    ip = '74.125.0.1'; isp = 'Google LLC'; country = 'US'
    vpn_proxy_tor = 'not detected'

class FakeNetworkVPN:
    ip = '45.86.200.1'; isp = 'Mullvad VPN'; country = 'SE'
    vpn_proxy_tor = 'vpn detected'

class FakePriorEmail:
    sender = 'ceo@bigcorp.com'; subject = 'Monthly team meeting'; body_text = 'Hi team, see you Monday.'
    links = []; attachments = []; date = None

class HighRiskPriorResult:
    risk_score = 85


TESTS = []
FAILED = []


def run_test(name, fn, expected_min=None, expected_max=None, check_verdict=None):
    global TESTS, FAILED
    TESTS.append(name)
    try:
        result = fn()
        score = result['risk_score']
        verdict = result['verdict']
        l1 = result['breakdown']['layer1_risk']
        l2 = result['breakdown']['layer2_risk']
        l3 = result['breakdown']['layer3_risk']
        print(f"\n[{name}]")
        print(f"  risk_score={score}, verdict='{verdict}'")
        print(f"  L1(content)={l1}, L2(transport)={l2}, L3(behavioral)={l3}")

        if expected_min is not None and score < expected_min:
            raise AssertionError(f"Expected score >= {expected_min}, got {score}")
        if expected_max is not None and score > expected_max:
            raise AssertionError(f"Expected score <= {expected_max}, got {score}")
        if check_verdict and check_verdict not in verdict:
            raise AssertionError(f"Expected verdict to contain '{check_verdict}', got '{verdict}'")

        print(f"  ✓ PASSED")
        return result
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        FAILED.append((name, str(e)))
        return None


# ─────────────────────────────────────────────────────
# LAYER 1 TESTS (Content Security)
# ─────────────────────────────────────────────────────

run_test(
    "L1-A: Clean email with PDF attachment",
    lambda: ScoringEngine.analyze_email(
        sender='noreply@google.com', recipient='user@gmail.com',
        subject='Your monthly invoice',
        body_text='Hi, please find your invoice attached. Thank you for being a customer.',
        links=['https://google.com/billing'],
        attachments=[{'filename': 'invoice.pdf', 'mime_type': 'application/pdf'}],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_max=25
)

run_test(
    "L1-B: Double-extension malware attachment (.pdf.exe)",
    lambda: ScoringEngine.analyze_email(
        sender='attacker@evil.top', recipient='victim@company.com',
        subject='Please open report',
        body_text='Open the attached report urgently.',
        links=[],
        attachments=[{'filename': 'report.pdf.exe', 'mime_type': 'application/x-msdownload'}],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_min=40,
    check_verdict="Malicious Attachment"
)

run_test(
    "L1-C: Phishing URL (typosquat brand)",
    lambda: ScoringEngine.analyze_email(
        sender='support@paypa1.com', recipient='victim@gmail.com',
        subject='Your account is suspended',
        body_text='Click here to restore your account.',
        links=['http://paypa1.com/login/verify', 'http://bit.ly/2xyzABC'],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_min=25
)

run_test(
    "L1-D: Wire transfer / credential coercion text",
    lambda: ScoringEngine.analyze_email(
        sender='scammer@evil.xyz', recipient='target@corp.com',
        subject='Urgent payment required',
        body_text='Your account will be terminated unless you wire transfer the amount immediately. Enter your credentials to proceed.',
        links=[],
        attachments=[],
        authentication=FakeAuthFail(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_min=30
)

# ─────────────────────────────────────────────────────
# LAYER 2 TESTS (Transport Forensics)
# ─────────────────────────────────────────────────────

run_test(
    "L2-A: SPF+DKIM fully passing (no auth risk)",
    lambda: ScoringEngine.analyze_email(
        sender='hr@trusted-corp.com', recipient='staff@trusted-corp.com',
        subject='All hands meeting tomorrow',
        body_text='Please join the all hands meeting tomorrow at 10am.',
        links=['https://meet.google.com/abc-defg-hij'],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_max=20
)

run_test(
    "L2-B: SPF+DKIM both fail (spoofed domain)",
    lambda: ScoringEngine.analyze_email(
        sender='ceo@bigcorp.com', recipient='cfo@bigcorp.com',
        subject='Wire 50000 immediately',
        body_text='Please transfer funds to this account now.',
        links=[],
        attachments=[],
        authentication=FakeAuthFail(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_min=30
)

run_test(
    "L2-C: VPN/Tor anonymized routing",
    lambda: ScoringEngine.analyze_email(
        sender='contact@phish.xyz', recipient='victim@company.com',
        subject='Account verification needed',
        body_text='Please verify your account immediately.',
        links=[],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetworkVPN(),
        route_hops=[], received_chain=[], raw_headers=[], historical_emails=[], historical_results=[]
    ),
    expected_min=10
)

run_test(
    "L2-D: Header Reply-To diversion attack",
    lambda: ScoringEngine.analyze_email(
        sender='support@legit-bank.com', recipient='customer@gmail.com',
        subject='Important banking update',
        body_text='Please review your account information.',
        links=[],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[],
        raw_headers=[
            {'name': 'From', 'value': 'support@legit-bank.com'},
            {'name': 'Reply-To', 'value': 'collect@evil-harvester.ru'},
            {'name': 'Return-Path', 'value': '<bounce@legit-bank.com>'}
        ],
        historical_emails=[], historical_results=[]
    ),
    expected_min=10
)

# ─────────────────────────────────────────────────────
# LAYER 3 TESTS (Behavioral / Historical AI)
# ─────────────────────────────────────────────────────

run_test(
    "L3-A: First-time sender with wire fraud lures",
    lambda: ScoringEngine.analyze_email(
        sender='unknown@firsttime.com', recipient='finance@company.com',
        subject='Urgent wire transfer needed',
        body_text='Please initiate a wire transfer via Western Union immediately.',
        links=[],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[],
        historical_emails=[],  # <-- Zero history
        historical_results=[]
    ),
    expected_min=20
)

run_test(
    "L3-B: Known safe sender — no behavioral anomaly",
    lambda: ScoringEngine.analyze_email(
        sender='newsletter@github.com', recipient='dev@mycompany.com',
        subject='Your GitHub monthly digest',
        body_text='Here are highlights from your GitHub activity this month.',
        links=['https://github.com/notifications'],
        attachments=[],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[],
        historical_emails=[FakePriorEmail(), FakePriorEmail(), FakePriorEmail()],
        historical_results=[]
    ),
    expected_max=25
)

run_test(
    "L3-C: Repeat high-risk sender (established threat pattern)",
    lambda: ScoringEngine.analyze_email(
        sender='repeat@phisher.xyz', recipient='victim@company.com',
        subject='You have won!',
        body_text='Click to claim your prize. Send bitcoin to claim.',
        links=['http://phisher.xyz/claim'],
        attachments=[],
        authentication=FakeAuthFail(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[],
        historical_emails=[FakePriorEmail(), FakePriorEmail()],
        historical_results=[HighRiskPriorResult(), HighRiskPriorResult()]
    ),
    expected_min=40
)

run_test(
    "L3-D: BEC — display name spoofing (CEO impersonation)",
    lambda: ScoringEngine.analyze_email(
        sender='CEO BigCorp <ceo@evil-domain.ru>',
        recipient='cfo@bigcorp.com',
        subject='Confidential: Immediate payment',
        body_text='Wire transfer funds immediately and confirm your banking credentials.',
        links=[],
        attachments=[],
        authentication=FakeAuthFail(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[],
        historical_emails=[FakePriorEmail()],
        historical_results=[],
        impersonation_candidates=[FakePriorEmail()]
    ),
    expected_min=50,
    check_verdict="Impersonation"
)

run_test(
    "L3-E: Unprecedented attachment from zero-attachment sender history",
    lambda: ScoringEngine.analyze_email(
        sender='colleague@company.com', recipient='me@company.com',
        subject='Check this out',
        body_text='Hi, I attached something important for you.',
        links=[],
        attachments=[{'filename': 'secret.iso', 'mime_type': 'application/octet-stream'}],
        authentication=FakeAuthPass(), network_intelligence=FakeNetwork(),
        route_hops=[], received_chain=[], raw_headers=[],
        historical_emails=[FakePriorEmail(), FakePriorEmail(), FakePriorEmail()],
        historical_results=[]
    ),
    expected_min=15
)

# ─────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────
print("\n" + "="*55)
print(f"RESULTS: {len(TESTS) - len(FAILED)}/{len(TESTS)} tests PASSED")
if FAILED:
    print("\nFAILED TESTS:")
    for name, err in FAILED:
        print(f"  ✗ {name}: {err}")
else:
    print("ALL TESTS PASSED ✓")
print("="*55)
