"""Vorpal security scanner service for code validation"""

import asyncio
import tempfile
import os
import json
import subprocess
import shlex
from typing import List, Dict, Any, Optional
import uuid
import logging

from ..config.settings import settings
from ..models.schemas import VulnerabilityDetail, ScanResult

logger = logging.getLogger(__name__)


class VorpalScanner:
    """Security scanner using Vorpal CLI tool."""
    
    def __init__(self, vorpal_path: Optional[str] = None):
        self.vorpal_path = vorpal_path or settings.vorpal_path
        
    async def scan_code(self, code: str, language: str, filename: str) -> ScanResult:
        """
        Scan code for security vulnerabilities.
        
        Args:
            code: Source code to scan
            language: Programming language of the code
            filename: Name of the file (used for proper language detection)
            
        Returns:
            ScanResult containing vulnerability information
        """
        request_id = str(uuid.uuid4())
        logger.debug(f"Starting scan {request_id} for {language} code")
        
        try:
            # Create temporary file with the code
            with tempfile.NamedTemporaryFile(
                mode='w', 
                suffix=f".{self._get_file_extension(language)}", 
                delete=False
            ) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            try:
                # Create temporary directory for results
                with tempfile.TemporaryDirectory() as temp_dir:
                    result_file = os.path.join(temp_dir, "scan_results.json")
                    
                    # Run Vorpal scanner - sanitize vorpal_path to prevent command injection
                    sanitized_vorpal_path = shlex.quote(self.vorpal_path)
                    cmd = [
                        sanitized_vorpal_path,
                        "-s", temp_file_path,
                        "-r", result_file
                    ]
                    
                    logger.debug(f"Running Vorpal command: {' '.join(cmd)}")
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await process.communicate()
                    
                    # Check if scan completed successfully
                    if process.returncode != 0:
                        error_msg = stderr.decode() if stderr else "Unknown error"
                        logger.warning(f"Vorpal scan failed with code {process.returncode}: {error_msg}")
                        return ScanResult(
                            request_id=request_id,
                            status=False,
                            message=f"Vorpal scan failed: {error_msg}",
                            vulnerabilities=[],
                            error=error_msg
                        )
                    
                    # Read results if file exists
                    vulnerabilities = []
                    if os.path.exists(result_file):
                        try:
                            with open(result_file, 'r') as f:
                                content = f.read().strip()
                                if content:
                                    results_data = json.loads(content)
                                    vulnerabilities = self._parse_vorpal_results(results_data)
                                # Empty file means no vulnerabilities found
                        except (json.JSONDecodeError, FileNotFoundError) as e:
                            logger.error(f"Failed to parse scan results: {e}")
                            return ScanResult(
                                request_id=request_id,
                                status=False,
                                message=f"Failed to parse scan results: {str(e)}",
                                vulnerabilities=[],
                                error=str(e)
                            )
                    # If no results file exists, assume no vulnerabilities found
                    
                    logger.info(f"Scan {request_id} completed with {len(vulnerabilities)} vulnerabilities")
                    return ScanResult(
                        request_id=request_id,
                        status=True,
                        message="Scan completed successfully",
                        vulnerabilities=vulnerabilities
                    )
                    
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file_path)
                except OSError:
                    pass
                    
        except Exception as e:
            logger.error(f"Scan {request_id} failed: {e}")
            return ScanResult(
                request_id=request_id,
                status=False,
                message=f"Scan failed with error: {str(e)}",
                vulnerabilities=[],
                error=str(e)
            )
    
    def _parse_vorpal_results(self, results_data: Dict[str, Any]) -> List[VulnerabilityDetail]:
        """
        Parse Vorpal JSON results into VulnerabilityDetail objects.
        
        Args:
            results_data: JSON data from Vorpal scan results
            
        Returns:
            List of VulnerabilityDetail objects
        """
        vulnerabilities = []
        
        try:
            # Handle None or empty results
            if not results_data:
                return vulnerabilities
            
            # Handle different possible result formats
            scan_results = None
            if isinstance(results_data, dict):
                if "results" in results_data:
                    scan_results = results_data["results"]
                elif "vulnerabilities" in results_data:
                    scan_results = results_data["vulnerabilities"]
                else:
                    scan_results = [results_data]
            elif isinstance(results_data, list):
                scan_results = results_data
            else:
                return vulnerabilities  # Unable to parse, return empty list
            
            # Handle None scan_results
            if not scan_results:
                return vulnerabilities
            
            for result in scan_results:
                if isinstance(result, dict):
                    vuln = VulnerabilityDetail(
                        ruleId=result.get("rule_id", result.get("ruleId", 0)),
                        language=result.get("language", "unknown"),
                        rule=result.get("rule_name", result.get("ruleName", result.get("rule", "Unknown Rule"))),
                        severity=result.get("severity", "medium"),
                        file=result.get("file", result.get("fileName", result.get("filename", "unknown"))),
                        line=result.get("line", result.get("lineNumber", result.get("line_number", 1))),
                        content=result.get("content", result.get("problematic_line", result.get("code", ""))),
                        remediationAdvice=result.get("remediationAdvise", result.get("remediationAadvice", result.get("advice", ""))),
                        description=result.get("description", result.get("desc", ""))
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Failed to parse vulnerability details: {e}")
            # If parsing fails, create a generic vulnerability entry
            vulnerabilities.append(VulnerabilityDetail(
                ruleId=0,
                language="unknown",
                rule="Parse Error",
                severity="low",
                file="unknown",
                line=1,
                content="",
                remediationAdvice="",
                description=f"Failed to parse scan results: {str(e)}"
            ))
        
        return vulnerabilities
    
    def _get_file_extension(self, language: str) -> str:
        """Get appropriate file extension for the language."""
        extensions = {
            "python": "py",
            "javascript": "js",
            "java": "java",
            "go": "go",
            "csharp": "cs",
            "c#": "cs"
        }
        return extensions.get(language.lower(), "txt")
    
    async def health_check(self) -> bool:
        """
        Check if Vorpal scanner is available and working.
        
        Returns:
            True if scanner is available, False otherwise
        """
        try:
            # Test with a simple command - sanitize vorpal_path to prevent command injection
            sanitized_vorpal_path = shlex.quote(self.vorpal_path)
            process = await asyncio.create_subprocess_exec(
                sanitized_vorpal_path,
                "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            is_healthy = process.returncode == 1  # Vorpal returns 1 for version command
            logger.debug(f"Vorpal health check: {'healthy' if is_healthy else 'unhealthy'}")
            return is_healthy
            
        except Exception as e:
            logger.warning(f"Vorpal health check failed: {e}")
            return False
