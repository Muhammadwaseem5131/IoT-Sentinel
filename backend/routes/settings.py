from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from security import settings_store

router = APIRouter(prefix="/api/settings", tags=["settings"])


class AiProviderRequest(BaseModel):
    provider: str = Field(..., min_length=1)
    api_key: str = ""


@router.get("/ai-provider")
def get_ai_provider():
    return settings_store.get_ai_provider()


@router.post("/ai-provider")
def post_ai_provider(req: AiProviderRequest):
    try:
        settings_store.set_ai_provider(req.provider, api_key=req.api_key or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return settings_store.get_ai_provider()


@router.delete("/ai-provider/{provider}")
def delete_ai_provider(provider: str):
    if provider not in settings_store.ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    settings_store.delete_provider(provider)
    return {"status": "deleted", "provider": provider}
