from ai_report.providers.base import ReportProvider


class ClaudeProvider(ReportProvider):
    name = "claude"

    def generate_report(self, findings_payload: dict, prompt: str) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=4096,
            system=prompt,
            messages=[{
                "role": "user",
                "content": _format_payload(findings_payload),
            }],
        )
        return "".join(block.text for block in message.content if getattr(block, "type", "") == "text")


def _format_payload(payload: dict) -> str:
    import json
    return json.dumps(payload, indent=2)
