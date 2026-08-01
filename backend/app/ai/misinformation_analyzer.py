import re
from app.ai.huggingface_client import HuggingFaceClient

MISINFO_PATTERNS = [
    (r"\b(government|treasury|federal reserve)\s+approved?\s+\$?\d+", "Unverified government stimulus or money distribution claim"),
    (r"\b(guaranteed|instant)\s+(payout|reward|stimulus|airdrop|token)\b", "Promoses guaranteed unearned financial rewards"),
    (r"\b(secret|suppressed)\s+(cure|remedy|treatment|formula)\b", "Conspiracy claim regarding suppressed medical or secret remedies"),
    (r"\b(share|forward)\s+(before|this)\s+(taken down|banned|deleted)\b", "Urges urgent sharing before censorship coercion technique"),
    (r"\b(official|mandated)\s+(distribution|airdrop|claim)\b", "Falsely asserts official administrative mandate for distribution"),
    (r"\b(click|connect)\s+wallet\s+to\s+claim\b", "High-risk crypto wallet connection trap disguised as news")
]


class MisinformationAnalyzer:
    @classmethod
    def analyze_text(cls, text: str, subject: str = "") -> dict:
        full_content = f"{subject}. {text}".strip()
        if not full_content:
            return cls._empty_report()

        # Split content into distinct sentences
        raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', full_content) if len(s.strip()) > 10]
        
        suspicious_sentences = []
        evidence = []
        misinfo_penalty = 0

        # Sentence-by-sentence pattern inspection
        for sentence in raw_sentences:
            sentence_lower = sentence.lower()
            sentence_flagged = False

            for pattern, reason in MISINFO_PATTERNS:
                if re.search(pattern, sentence_lower):
                    if not sentence_flagged:
                        suspicious_sentences.append({
                            "sentence": sentence,
                            "risk": reason
                        })
                        sentence_flagged = True
                    if reason not in evidence:
                        evidence.append(reason)
                    misinfo_penalty += 25

        # Query HuggingFace for zero-shot misinformation probability
        hf_labels = ["unverified fake news or misinformation", "verified factual news or communication"]
        hf_result = HuggingFaceClient.classify_text(full_content, hf_labels)
        misinfo_prob = hf_result.get("unverified fake news or misinformation", 0.0)

        if misinfo_prob > 0.6:
            misinfo_penalty += int(misinfo_prob * 30)
            if "NLP model detected high probability of unverified propaganda" not in evidence:
                evidence.append("HuggingFace NLP model detected high probability of unverified propaganda or sensationalism")

        # Compute Credibility Score (100 = 完全 Factual, 0 = High Fake News)
        credibility_score = max(0, min(100, 100 - misinfo_penalty))
        confidence = 0.92 if suspicious_sentences else 0.88

        if credibility_score >= 80 and not evidence:
            evidence.append("Content aligns with standard factual correspondence and lacks sensationalist propaganda triggers.")

        return {
            "credibility_score": credibility_score,
            "confidence": confidence,
            "suspicious_sentences": suspicious_sentences,
            "evidence": evidence
        }

    @staticmethod
    def _empty_report() -> dict:
        return {
            "credibility_score": 100,
            "confidence": 1.0,
            "suspicious_sentences": [],
            "evidence": ["Empty content."]
        }
