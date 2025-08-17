"""API routes for code remediation service"""

from fastapi import APIRouter, HTTPException, Depends
import logging
from typing import List

from ..models.schemas import (
    RemediationRequest, 
    RemediationResponse, 
    HealthResponse,
    ErrorResponse
)
from ..services.ollama_client import OllamaClient
from ..services.vorpal_scanner import VorpalScanner
from ..config.settings import settings

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter()

# Dependency injection for services
def get_ollama_client() -> OllamaClient:
    """Get Ollama client instance"""
    return OllamaClient()

def get_vorpal_scanner() -> VorpalScanner:
    """Get Vorpal scanner instance"""
    return VorpalScanner()


@router.post(
    "/api/remediation",
    response_model=RemediationResponse,
    responses={
        200: {"model": RemediationResponse},
        422: {"model": ErrorResponse, "description": "Unable to generate secure code"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    summary="Generate secure code remediation",
    description="Generate AI-powered code remediation with security validation"
)
async def remediate_code(
    request: RemediationRequest,
    ollama_client: OllamaClient = Depends(get_ollama_client),
    vorpal_scanner: VorpalScanner = Depends(get_vorpal_scanner)
) -> RemediationResponse:
    """
    Generate secure code remediation based on vulnerability details.
    
    This endpoint:
    1. Receives vulnerability details
    2. Sends request to Ollama for AI-based remediation
    3. Scans the generated code with Vorpal for security issues
    4. Retries up to 5 times if vulnerabilities are found
    """
    logger.info(f"Processing remediation request for {request.language} - {request.ruleName}")
    
    max_retries = settings.max_retries
    conversation_history = []
    
    # Validate language
    if request.language.lower() not in [lang.lower() for lang in settings.allowed_languages]:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported language: {request.language}. Supported languages: {', '.join(settings.allowed_languages)}"
        )
    
    # Initial system prompt for the AI model
    system_prompt = """You are a security remediation expert. Your task is to provide ONLY secure code snippets that fix the specified vulnerability. 

Rules:
1. Respond with ONLY the code snippet - no explanations, no markdown formatting
2. The code must be syntactically correct and secure
3. Use the exact programming language specified in the request
4. Focus specifically on fixing the vulnerability described

The code should demonstrate the secure way to implement the functionality."""

    # Initial user prompt
    user_prompt = f"""
Language: {request.language}
Rule: {request.ruleName}
Description: {request.description}
Remediation Advice: {request.remediationAdvice}

Provide a secure code snippet that fixes this vulnerability.
"""

    for attempt in range(max_retries):
        try:
            logger.debug(f"Remediation attempt {attempt + 1}/{max_retries}")
            
            # Get remediation from Ollama using chat API
            if attempt == 0:
                # First attempt with original prompt
                remediated_code = await ollama_client.generate_remediation(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    conversation_history=[]
                )
            else:
                # Subsequent attempts with full conversation history including Vorpal feedback
                enhanced_user_prompt = "Based on the previous security analysis feedback, please provide an improved and more secure version."
                
                remediated_code = await ollama_client.generate_remediation(
                    system_prompt=system_prompt,
                    user_prompt=enhanced_user_prompt,
                    conversation_history=conversation_history
                )
                
                logger.debug(f"Retry attempt {attempt + 1} with {len(conversation_history)} messages in conversation history")
            
            if not remediated_code.strip():
                raise HTTPException(status_code=500, detail="Empty response from AI model")
            
            # Scan with Vorpal
            scan_result = await vorpal_scanner.scan_code(
                code=remediated_code,
                language=request.language,
                filename=f"remediation.{_get_file_extension(request.language)}"
            )
            
            if scan_result.has_vulnerabilities():
                # Add assistant's response and Vorpal analysis to conversation history
                vulnerability_details = scan_result.get_vulnerability_summary()
                # Add assistant's code attempt
                conversation_history.append({
                    "role": "assistant", 
                    "content": remediated_code
                })
                
                # Add Vorpal analysis result as a user message for better model understanding
                conversation_history.append({
                    "role": "vorpal_results",
                    "content": f"The security scanner found these vulnerabilities in your code: {vulnerability_details}\n\nPlease fix these specific security issues and provide a corrected version."
                })
                
                logger.warning(f"Attempt {attempt + 1} had vulnerabilities: {vulnerability_details}")
                logger.debug(f"Added Vorpal analysis to conversation history: {vulnerability_details}")
                
                if attempt == max_retries - 1:
                    # Last attempt failed
                    raise HTTPException(
                        status_code=422, 
                        detail=f"Unable to generate secure code after {max_retries} attempts. Last vulnerabilities: {vulnerability_details}"
                    )
                continue
            else:
                # Success! No vulnerabilities found
                logger.info(f"Successfully generated secure code after {attempt + 1} attempts")
                return RemediationResponse(remediated_code=remediated_code)
                
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error in attempt {attempt + 1}: {e}")
            if attempt == max_retries - 1:
                raise HTTPException(status_code=500, detail=f"Failed to generate remediation: {str(e)}")
            # Add error to conversation history for context
            conversation_history.append({
                "role": "system",
                "content": f"Error occurred in previous attempt: {str(e)}"
            })
            continue
    
    raise HTTPException(status_code=500, detail="Unexpected error in remediation process")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check if the service is healthy and all dependencies are available"
)
async def health_check(
    ollama_client: OllamaClient = Depends(get_ollama_client),
    vorpal_scanner: VorpalScanner = Depends(get_vorpal_scanner)
) -> HealthResponse:
    """Health check endpoint with dependency validation."""
    
    try:
        # Check Ollama service
        ollama_healthy = await ollama_client.health_check()
        if not ollama_healthy:
            logger.warning("Ollama service is not healthy")
        
        # Check Vorpal scanner
        vorpal_healthy = await vorpal_scanner.health_check()
        if not vorpal_healthy:
            logger.warning("Vorpal scanner is not healthy")
        
        # Service is healthy if basic functionality works
        # Dependencies being down is logged but doesn't fail health check
        return HealthResponse(status="healthy")
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")


def _get_file_extension(language: str) -> str:
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
