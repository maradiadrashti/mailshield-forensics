import os
import requests
from app.core.config import settings

HF_INFERENCE_API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"


class HuggingFaceClient:
    @staticmethod
    def classify_text(text: str, candidate_labels: list[str]) -> dict:
        """
        Queries HuggingFace Zero-Shot Classification API for candidate threat labels.
        """
        token = getattr(settings, "HUGGINGFACE_API_TOKEN", os.getenv("HUGGINGFACE_API_TOKEN", ""))
        
        headers = {}
        if token and token != "your_huggingface_api_token_here":
            headers["Authorization"] = f"Bearer {token}"

        payload = {
            "inputs": text[:1000],  # Truncate to first 1000 chars for optimal performance
            "parameters": {
                "candidate_labels": candidate_labels,
                "multi_label": True
            }
        }

        try:
            res = requests.post(HF_INFERENCE_API_URL, headers=headers, json=payload, timeout=8)
            if res.status_code == 200:
                data = res.json()
                # Return label to score dictionary mapping
                labels = data.get("labels", [])
                scores = data.get("scores", [])
                return dict(zip(labels, scores))
        except Exception as e:
            print(f"HuggingFace Inference API request warning: {e}")

        # Return empty dict if API is unavailable or rate limited (Scoring Engine falls back to local NLP heuristics)
        return {}
