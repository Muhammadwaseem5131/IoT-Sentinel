import json

from ai_report.providers.base import ReportProvider


class GroqProvider(ReportProvider):
    name = "groq"

    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        from groq import Groq

        client = Groq(api_key=self.api_key)
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(findings_payload, indent=2)},
            ],
        )
        return response.choices[0].message.content or ""
