import json

from ai_report.providers.base import ReportProvider


class OpenAIProvider(ReportProvider):
    name = "openai"

    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=4096,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(findings_payload, indent=2)},
            ],
        )
        return response.choices[0].message.content or ""
