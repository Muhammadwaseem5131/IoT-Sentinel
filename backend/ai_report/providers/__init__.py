from ai_report.providers.claude_provider import ClaudeProvider
from ai_report.providers.gemini_provider import GeminiProvider
from ai_report.providers.groq_provider import GroqProvider
from ai_report.providers.ollama_provider import OllamaProvider
from ai_report.providers.openai_provider import OpenAIProvider

PROVIDERS = {
    p.name: p
    for p in (ClaudeProvider, OpenAIProvider, GeminiProvider, GroqProvider, OllamaProvider)
}
