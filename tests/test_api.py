"""Test cases for API endpoints"""

import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from src.remediation.models.schemas import ScanResult, VulnerabilityDetail


class TestRemediationAPI:
    """Test cases for the remediation API endpoint"""

    def test_health_endpoint(self, client: TestClient):
        """Test the health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_successful_remediation(
        self, 
        mock_get_scanner, 
        mock_get_ollama, 
        client: TestClient,
        mock_ollama_client,
        mock_vorpal_scanner,
        sample_remediation_request
    ):
        """Test successful code remediation"""
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner
        
        response = client.post("/api/remediation", json=sample_remediation_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "remediated_code" in data
        assert data["remediated_code"] == "secure_code_example"

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_remediation_with_retries(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient,
        mock_ollama_client,
        mock_vorpal_scanner_with_vulnerabilities,
        sample_remediation_request
    ):
        """Test remediation that requires retries due to vulnerabilities"""
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner_with_vulnerabilities
        
        # Configure scanner to return vulnerabilities first, then clean on retry
        scan_results = [
            # First scan - with vulnerabilities
            ScanResult(
                request_id="test-1",
                status=True,
                message="Scan completed",
                vulnerabilities=[VulnerabilityDetail(
                    rule_id=1,
                    language="python",
                    rule_name="SQL Injection",
                    severity="high",
                    file_name="test.py",
                    line=1,
                    length=10,
                    problematic_line="bad code",
                    remediation_advise="fix it",
                    description="vulnerability found"
                )]
            ),
            # Second scan - clean
            ScanResult(
                request_id="test-2",
                status=True,
                message="Scan completed",
                vulnerabilities=[]
            )
        ]
        
        mock_vorpal_scanner_with_vulnerabilities.scan_code.side_effect = scan_results
        
        response = client.post("/api/remediation", json=sample_remediation_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "remediated_code" in data

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_max_retries_exceeded(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient,
        mock_ollama_client,
        mock_vorpal_scanner_with_vulnerabilities,
        sample_remediation_request
    ):
        """Test when max retries are exceeded"""
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner_with_vulnerabilities
        
        response = client.post("/api/remediation", json=sample_remediation_request)
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert "Unable to generate secure code after 5 attempts" in data["detail"]

    def test_invalid_language(self, client: TestClient):
        """Test with unsupported language"""
        request_data = {
            "language": "cobol",
            "ruleName": "Some Rule",
            "description": "Some description",
            "remediationAdvice": "Some advice"
        }
        
        response = client.post("/api/remediation", json=request_data)
        
        assert response.status_code == 400
        data = response.json()
        assert "Unsupported language" in data["detail"]

    def test_missing_required_fields(self, client: TestClient):
        """Test with missing required fields"""
        request_data = {
            "language": "python"
            # Missing other required fields
        }
        
        response = client.post("/api/remediation", json=request_data)
        
        assert response.status_code == 422

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_ollama_service_error(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient,
        mock_vorpal_scanner,
        sample_remediation_request
    ):
        """Test when Ollama service fails"""
        mock_ollama_client = AsyncMock()
        mock_ollama_client.generate_remediation.side_effect = Exception("Ollama error")
        
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner
        
        response = client.post("/api/remediation", json=sample_remediation_request)
        
        assert response.status_code == 500

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_empty_ollama_response(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient,
        mock_vorpal_scanner,
        sample_remediation_request
    ):
        """Test when Ollama returns empty response"""
        mock_ollama_client = AsyncMock()
        mock_ollama_client.generate_remediation.return_value = ""
        
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner
        
        response = client.post("/api/remediation", json=sample_remediation_request)
        
        assert response.status_code == 500
        data = response.json()
        assert "Empty response from AI model" in data["detail"]


class TestHealthAPI:
    """Test cases for health check endpoint"""

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_health_check_success(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient,
        mock_ollama_client,
        mock_vorpal_scanner
    ):
        """Test successful health check"""
        mock_get_ollama.return_value = mock_ollama_client
        mock_get_scanner.return_value = mock_vorpal_scanner
        
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    @patch("src.remediation.api.routes.get_ollama_client")
    @patch("src.remediation.api.routes.get_vorpal_scanner")
    def test_health_check_with_service_errors(
        self,
        mock_get_scanner,
        mock_get_ollama,
        client: TestClient
    ):
        """Test health check when services have issues"""
        mock_ollama = AsyncMock()
        mock_ollama.health_check.return_value = False
        
        mock_scanner = AsyncMock()
        mock_scanner.health_check.return_value = False
        
        mock_get_ollama.return_value = mock_ollama
        mock_get_scanner.return_value = mock_scanner
        
        response = client.get("/health")
        
        # Service should still be healthy even if dependencies are down
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
