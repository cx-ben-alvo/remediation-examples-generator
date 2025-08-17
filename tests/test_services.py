"""Test cases for service modules"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, mock_open
import json
import tempfile
import os

from src.remediation.services.ollama_client import OllamaClient
from src.remediation.services.vorpal_scanner import VorpalScanner
from src.remediation.models.schemas import VulnerabilityDetail, ScanResult


class TestOllamaClient:
    """Test cases for OllamaClient"""

    def test_init_default_settings(self):
        """Test OllamaClient initialization with default settings"""
        client = OllamaClient()
        assert client.base_url == "http://127.0.0.1:11434"
        assert client.model == "llama3.2"

    def test_init_custom_settings(self):
        """Test OllamaClient initialization with custom settings"""
        client = OllamaClient("http://custom:8080", "custom-model")
        assert client.base_url == "http://custom:8080"
        assert client.model == "custom-model"

    @pytest.mark.asyncio
    async def test_generate_remediation_success(self):
        """Test successful code generation"""
        client = OllamaClient()
        
        mock_response = {
            "response": "def secure_function():\n    return 'safe code'"
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.return_value.status_code = 200
            mock_instance.post.return_value.json.return_value = mock_response
            
            result = await client.generate_remediation("test prompt")
            
            assert result == "def secure_function():\n    return 'safe code'"

    @pytest.mark.asyncio
    async def test_generate_remediation_http_error(self):
        """Test handling of HTTP errors"""
        client = OllamaClient()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.return_value.status_code = 500
            mock_instance.post.return_value.text = "Internal Server Error"
            
            with pytest.raises(Exception, match="Ollama request failed with status 500"):
                await client.generate_remediation("test prompt")

    @pytest.mark.asyncio
    async def test_generate_remediation_timeout(self):
        """Test handling of timeout errors"""
        client = OllamaClient()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.side_effect = httpx.TimeoutException("Timeout")
            
            with pytest.raises(Exception, match="Timeout while communicating with Ollama service"):
                await client.generate_remediation("test prompt")

    @pytest.mark.asyncio
    async def test_generate_remediation_invalid_response(self):
        """Test handling of invalid response format"""
        client = OllamaClient()
        
        mock_response = {"invalid": "format"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.return_value.status_code = 200
            mock_instance.post.return_value.json.return_value = mock_response
            
            with pytest.raises(Exception, match="Invalid response format from Ollama"):
                await client.generate_remediation("test prompt")

    def test_clean_code_response_with_markdown(self):
        """Test cleaning markdown formatting from response"""
        client = OllamaClient()
        
        response_with_markdown = """```python
def secure_function():
    return 'safe code'
```"""
        
        cleaned = client._clean_code_response(response_with_markdown)
        expected = "def secure_function():\n    return 'safe code'"
        assert cleaned == expected

    def test_clean_code_response_with_explanations(self):
        """Test cleaning explanations from response"""
        client = OllamaClient()
        
        response_with_explanations = """Here is the secure code:
def secure_function():
    return 'safe code'
This code is safe because..."""
        
        cleaned = client._clean_code_response(response_with_explanations)
        assert "Here is the secure code:" not in cleaned
        assert "def secure_function():" in cleaned

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check"""
        client = OllamaClient()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value.status_code = 200
            
            result = await client.health_check()
            assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test failed health check"""
        client = OllamaClient()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.side_effect = httpx.ConnectError("Connection failed")
            
            result = await client.health_check()
            assert result is False


class TestVorpalScanner:
    """Test cases for VorpalScanner"""

    def test_init_default_path(self):
        """Test VorpalScanner initialization with default path"""
        scanner = VorpalScanner()
        assert scanner.vorpal_path is not None

    def test_init_custom_path(self):
        """Test VorpalScanner initialization with custom path"""
        custom_path = "/custom/path/to/vorpal"
        scanner = VorpalScanner(custom_path)
        assert scanner.vorpal_path == custom_path

    def test_get_file_extension(self):
        """Test file extension mapping"""
        scanner = VorpalScanner()
        
        assert scanner._get_file_extension("python") == "py"
        assert scanner._get_file_extension("javascript") == "js"
        assert scanner._get_file_extension("java") == "java"
        assert scanner._get_file_extension("go") == "go"
        assert scanner._get_file_extension("csharp") == "cs"
        assert scanner._get_file_extension("c#") == "cs"
        assert scanner._get_file_extension("unknown") == "txt"

    @pytest.mark.asyncio
    async def test_scan_code_no_vulnerabilities(self):
        """Test scanning code with no vulnerabilities found"""
        scanner = VorpalScanner()
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock successful process execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Mock empty results file
            with patch("os.path.exists", return_value=False):
                result = await scanner.scan_code("safe code", "python", "test.py")
                
                assert result.status is True
                assert len(result.vulnerabilities) == 0
                assert result.message == "Scan completed successfully"

    @pytest.mark.asyncio
    async def test_scan_code_with_vulnerabilities(self):
        """Test scanning code with vulnerabilities found"""
        scanner = VorpalScanner()
        
        vulnerability_data = {
            "results": [{
                "ruleId": 1,
                "language": "python",
                "ruleName": "SQL Injection",
                "severity": "high",
                "fileName": "test.py",
                "line": 5,
                "length": 20,
                "problematicLine": "query = 'SELECT * FROM users'",
                "remediationAdvise": "Use parameterized queries",
                "description": "SQL injection vulnerability"
            }]
        }
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock successful process execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Mock results file with vulnerabilities
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", mock_open(read_data=json.dumps(vulnerability_data))):
                    result = await scanner.scan_code("unsafe code", "python", "test.py")
                    
                    assert result.status is True
                    assert len(result.vulnerabilities) == 1
                    assert result.vulnerabilities[0].rule_name == "SQL Injection"
                    assert result.vulnerabilities[0].severity == "high"

    @pytest.mark.asyncio
    async def test_scan_code_process_failure(self):
        """Test handling of scanner process failure"""
        scanner = VorpalScanner()
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock failed process execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Scanner error")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            result = await scanner.scan_code("code", "python", "test.py")
            
            assert result.status is False
            assert "Vorpal scan failed" in result.message
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_scan_code_json_parse_error(self):
        """Test handling of JSON parsing errors"""
        scanner = VorpalScanner()
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock successful process execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Mock results file with invalid JSON
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", mock_open(read_data="invalid json")):
                    result = await scanner.scan_code("code", "python", "test.py")
                    
                    assert result.status is False
                    assert "Failed to parse scan results" in result.message

    def test_parse_vorpal_results_empty_data(self):
        """Test parsing empty or None results"""
        scanner = VorpalScanner()
        
        # Test None data
        result = scanner._parse_vorpal_results(None)
        assert len(result) == 0
        
        # Test empty dict
        result = scanner._parse_vorpal_results({})
        assert len(result) == 0
        
        # Test empty list
        result = scanner._parse_vorpal_results([])
        assert len(result) == 0

    def test_parse_vorpal_results_different_formats(self):
        """Test parsing results in different formats"""
        scanner = VorpalScanner()
        
        vulnerability_data = {
            "ruleId": 1,
            "language": "python",
            "ruleName": "Test Rule",
            "severity": "medium",
            "fileName": "test.py",
            "line": 1,
            "length": 10,
            "problematicLine": "bad code",
            "remediationAdvise": "fix it",
            "description": "test vulnerability"
        }
        
        # Test with "results" key
        data_with_results = {"results": [vulnerability_data]}
        result = scanner._parse_vorpal_results(data_with_results)
        assert len(result) == 1
        assert result[0].rule_name == "Test Rule"
        
        # Test with "vulnerabilities" key
        data_with_vulns = {"vulnerabilities": [vulnerability_data]}
        result = scanner._parse_vorpal_results(data_with_vulns)
        assert len(result) == 1
        assert result[0].rule_name == "Test Rule"
        
        # Test with direct list
        result = scanner._parse_vorpal_results([vulnerability_data])
        assert len(result) == 1
        assert result[0].rule_name == "Test Rule"

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check"""
        scanner = VorpalScanner()
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock successful version command (returns 1 for Vorpal)
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"v1.1.4", b"")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            result = await scanner.health_check()
            assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test failed health check"""
        scanner = VorpalScanner()
        
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_subprocess.side_effect = Exception("Command not found")
            
            result = await scanner.health_check()
            assert result is False
