from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    gemini_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("GEMINI_API_KEY", "CRYPTOH_GEMINI_API_KEY"),
    )
    model: str = "gemma-4"
    window_seconds: float = 5.0
    baseline_seconds: float = 60.0
    output_dir: str = "cryptoh-report"

    model_config = {"env_prefix": "CRYPTOH_", "extra": "ignore"}


settings = Settings()
