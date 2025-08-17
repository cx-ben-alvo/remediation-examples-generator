"""Pydantic models for request/response schemas"""

from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class LanguageEnum(str, Enum):
    """Supported programming languages"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    GO = "go"
    CSHARP = "csharp"
    CS = "c#"


class RemediationRequest(BaseModel):
    """Request model for code remediation"""
    language: str = Field(..., description="Programming language of the code")
    ruleName: str = Field(..., alias="ruleName", description="Name of the security rule that was violated")
    description: str = Field(..., description="Description of the vulnerability")
    remediationAdvice: str = Field(..., alias="remediationAdvice", description="Advice on how to fix the vulnerability")

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "language": "go",
                "ruleName": "Unsafe SQL Query Construction",
                "description": "Dynamically constructing SQL queries through string concatenation can lead to SQL injection vulnerabilities",
                "remediationAdvice": "Consider using parameterized queries with SqlCommand and not concatenate strings to form SQL queries."
            }
        }


class RemediationResponse(BaseModel):
    """Response model for code remediation"""
    remediated_code: str = Field(..., description="The remediated code snippet")

    class Config:
        json_schema_extra = {
            "example": {
                "remediated_code": "query: `SELECT id, username, email, role FROM users WHERE username = ? AND password = ?`,\n        params: [username, password],"
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(default="healthy", description="Service health status")


class ErrorResponse(BaseModel):
    """Error response model"""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Specific error code")


class VulnerabilityDetail(BaseModel):
    """Model for vulnerability details from scanner"""
    ruleId: int
    language: str
    rule: str
    severity: str
    file: str
    line: int
    content: str
    remediationAdvice: str
    description: str


class ScanResult(BaseModel):
    """Model for scan result from security scanner"""
    request_id: str
    status: bool
    message: str
    vulnerabilities: List[VulnerabilityDetail]
    error: Optional[str] = None

    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found"""
        return len(self.vulnerabilities) > 0

    def get_vulnerability_summary(self) -> str:
        """Get a summary of found vulnerabilities"""
        if not self.vulnerabilities:
            return "No vulnerabilities found"
        
        summary = []
        for vuln in self.vulnerabilities:
            summary.append(f"{vuln.rule} (line {vuln.line}: {vuln.content}) description: {vuln.description}")
        
        return "; ".join(summary)
