import json

from ai_report.providers.base import ReportProvider


class GeminiProvider(ReportProvider):
    name = "gemini"

    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        from google import genai

        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=f"{prompt}\n\nFindings data:\n{json.dumps(findings_payload, indent=2)}",
        )
        return response.text or ""
