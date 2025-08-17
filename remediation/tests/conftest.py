"""Pytest configuration and fixtures"""

import pytest
import asyncio
from typing import Generator, AsyncGenerator
from unittest.mock import AsyncMock, Mock

from fastapi.testclient import TestClient

from src.remediation.main import create_app
from src.remediation.services.ollama_client import OllamaClient
from src.remediation.services.vorpal_scanner import VorpalScanner
from src.remediation.models.schemas import ScanResult, VulnerabilityDetail


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the FastAPI app."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def mock_ollama_client() -> Mock:
    """Create a mock Ollama client."""
    mock = AsyncMock(spec=OllamaClient)
    mock.health_check.return_value = True
    mock.generate_remediation.return_value = "secure_code_example"
    return mock


@pytest.fixture
def mock_vorpal_scanner() -> Mock:
    """Create a mock Vorpal scanner."""
    mock = AsyncMock(spec=VorpalScanner)
    mock.health_check.return_value = True
    
    # Default to no vulnerabilities found
    mock.scan_code.return_value = ScanResult(
        request_id="test-123",
        status=True,
        message="Scan completed successfully",
        vulnerabilities=[]
    )
    return mock


@pytest.fixture
def mock_vorpal_scanner_with_vulnerabilities() -> Mock:
    """Create a mock Vorpal scanner that finds vulnerabilities."""
    mock = AsyncMock(spec=VorpalScanner)
    mock.health_check.return_value = True
    
    vulnerability = VulnerabilityDetail(
        rule_id=1,
        language="python",
        rule_name="SQL Injection",
        severity="high",
        file_name="test.py",
        line=1,
        length=10,
        problematic_line="query = 'SELECT * FROM users WHERE id = ' + user_id",
        remediation_advise="Use parameterized queries",
        description="SQL injection vulnerability"
    )
    
    mock.scan_code.return_value = ScanResult(
        request_id="test-123",
        status=True,
        message="Scan completed successfully",
        vulnerabilities=[vulnerability]
    )
    return mock


@pytest.fixture
def sample_remediation_request() -> dict:
    """Sample remediation request data."""
    return {
        "language": "python",
        "ruleName": "SQL Injection",
        "description": "SQL injection vulnerability in user query",
        "remediationAdvice": "Use parameterized queries instead of string concatenation"
    }


@pytest.fixture
def sample_go_request() -> dict:
    """Sample Go remediation request data."""
    return {
        "language": "go",
        "ruleName": "Unsafe SQL Query Construction",
        "description": "Dynamically constructing SQL queries through string concatenation can lead to SQL injection vulnerabilities",
        "remediationAdvice": "Consider using parameterized queries with SqlCommand and not concatenate strings to form SQL queries."
    }
