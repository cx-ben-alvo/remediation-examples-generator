"""Application configuration settings"""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    app_name: str = "Code Remediation Service"
    app_version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    
    # Ollama Configuration
    ollama_host: str = "127.0.0.1"
    ollama_port: int = 11434
    ollama_model: str = "llama3.2"
    ollama_timeout: int = 60
    
    # Vorpal Scanner Configuration
    vorpal_path: Optional[str] = None
    max_retries: int = 5
    
    # Security
    allowed_languages: list[str] = ["python", "javascript", "java", "go", "csharp", "c#"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set default Vorpal path if not configured
        if self.vorpal_path is None:
            project_root = Path(__file__).parent.parent.parent.parent
            self.vorpal_path = str(project_root / "resources" / "vorpal_cli_darwin_arm64")

    @property
    def ollama_base_url(self) -> str:
        """Get the full Ollama base URL"""
        return f"http://{self.ollama_host}:{self.ollama_port}"


# Global settings instance
settings = Settings()
