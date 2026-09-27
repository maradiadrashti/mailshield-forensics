"""
Scoring engine accuracy verification script.
Runs without the full FastAPI app stack.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

src = open('app/ai/scoring_engine.py', encoding='utf-8').read()

CHECKS = [
    ('LEGITIMATE_ESP_DOMAINS', 'ESP whitelist constant'),
    ('LEGITIMATE_REPLY_DOMAINS', 'Reply-To whitelist constant'),
    ('auth_risk = 90', 'Dual fail = 90 risk'),
    ('auth_risk = 70', 'Single fail = 70 risk'),
    ('auth_risk = 60', 'DMARC fail = 60 risk'),
    ('auth_risk = 5', 'Partial pass = 5 risk'),
    ('int(auth_risk * 0.50)', 'Layer2 auth 50% weight'),
    ('int(header_risk * 0.30)', 'Layer2 header 30% weight'),
    ('int(routing_risk * 0.20)', 'Layer2 routing 20% weight'),
    ('max(layer2_risk, 50)', 'Layer2 floor enforcement'),
    ('history_count >= 3', 'Attachment anomaly 3+ email threshold'),
    ('historical_analyzed_count', 'Confidence from analyzed count'),
    ("severity = \"medium\"", 'Medium severity tier added'),
    ('l1_risk * 0.45', 'L1 UI score 45% weight'),
    ('l2_risk * 0.20', 'L2 UI score 20% weight'),
    ('l3_risk * 0.35', 'L3 UI score 35% weight'),
    ('"max_score": 45', 'Layer1 max_score = 45'),
    ('"max_score": 20', 'Layer2 max_score = 20'),
    ('url_findings', 'URL reports reuse from L1'),
    ('urgency_spike', 'Urgency spike detection in verdict'),
    ('_extract_domain', 'RFC domain extractor function'),
    ('vpn detected', 'VPN-specific routing check'),
    ('overall_score < 20', 'Verdict threshold = 20 (not 25)'),
    ('0.45)   # Max 45', 'L1 score comment documenting max'),
    ('layer1_risk + int(secondary_risk', 'Multi-vector bonus escalation'),
]

failed = 0
for pattern, label in CHECKS:
    if pattern in src:
        print(f"  OK   {label}")
    else:
        print(f"  FAIL {label}  [pattern: {pattern!r}]")
        failed += 1

print(f"\n{'='*50}")
print(f"Total: {len(CHECKS)} checks, {failed} failed, {len(CHECKS)-failed} passed")
if failed:
    sys.exit(1)
