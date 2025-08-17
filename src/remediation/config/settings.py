"""Application configuration settings"""

import os
from pathlib import Path
from typing import Optional
import re

from pydantic_settings import BaseSettings
from pydantic import validator


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
    vorpal_path: str = "/usr/local/bin/vorpal"  # Default container path
    max_retries: int = 5
    
    # Security
    allowed_languages: list[str] = ["python", "javascript", "java", "go", "csharp", "c#"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Fallback to local development path if container path doesn't exist
        if not os.path.exists(self.vorpal_path):
            project_root = Path(__file__).parent.parent.parent.parent
            local_path = project_root / "resources" / "vorpal_cli_darwin_arm64"
            if local_path.exists():
                self.vorpal_path = str(local_path)

    @validator("ollama_host")
    def validate_ollama_host(cls, v: str) -> str:
        """Validate Ollama host format"""
        # Allow localhost, IP addresses, domain names, and Docker service names
        ip_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
        service_name_pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$")
        
        if v in ["localhost", "127.0.0.1"]:
            return v
        if ip_pattern.match(v) or domain_pattern.match(v) or service_name_pattern.match(v):
            return v
        raise ValueError("Invalid host format. Must be localhost, IP address, domain name, or service name")

    @validator("ollama_port")
    def validate_ollama_port(cls, v: int) -> int:
        """Validate Ollama port number"""
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

    @property
    def ollama_base_url(self) -> str:
        """Get the full Ollama base URL"""
        return f"http://{self.ollama_host}:{self.ollama_port}"


# Global settings instance
settings = Settings()
