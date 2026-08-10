import json

import requests

from ai_report.providers.base import ReportProvider

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3:8b"


class OllamaProvider(ReportProvider):
    """Local provider. No API key, no data leaves the machine."""

    name = "ollama"

    def __init__(self, api_key: str = "", model: str = DEFAULT_MODEL, **kwargs):
        super().__init__(api_key=api_key, **kwargs)
        self.model = model

    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": self.model,
                "prompt": f"{prompt}\n\nFindings data:\n{json.dumps(findings_payload, indent=2)}",
                "stream": False,
            },
            timeout=300,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
