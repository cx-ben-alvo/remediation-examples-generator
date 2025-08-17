"""Ollama AI service client for code remediation"""

import httpx
import json
from typing import Optional
import asyncio
import logging

from ..config.settings import settings

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for communicating with Ollama AI service."""
    
    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.ollama_base_url
        self.model = model or settings.ollama_model
        
    async def generate_remediation(self, system_prompt: str, user_prompt: str, conversation_history: list = None) -> str:
        """
        Generate code remediation using Ollama chat API.
        
        Args:
            system_prompt: The system prompt with instructions
            user_prompt: The user prompt with vulnerability details
            conversation_history: Previous conversation messages for context
            
        Returns:
            The generated code remediation
            
        Raises:
            Exception: If the request fails or returns invalid response
        """
        url = f"{self.base_url}/api/chat"
        
        # Build messages array
        messages = []
        
        # Add system message
        messages.append({"role": "system", "content": system_prompt})
        
        # Add conversation history if provided
        if conversation_history:
            messages.extend(conversation_history)
        
        # Add current user message
        messages.append({"role": "user", "content": user_prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for more deterministic output
                "top_p": 0.9,
                "top_k": 40,
                "num_predict": 1000,  # Limit response length
            }
        }
        
        logger.debug(f"Sending chat request to Ollama: {self.base_url}")
        logger.debug(f"Messages being sent: {len(messages)} total messages")
        if conversation_history:
            logger.debug(f"Conversation history includes {len(conversation_history)} previous messages")
            for i, msg in enumerate(conversation_history):
                logger.debug(f"  History {i+1}: {msg['role']} - {msg['content'][:100]}...")
        
        try:
            async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code != 200:
                    error_msg = f"Ollama request failed with status {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                
                result = response.json()
                
                if "message" not in result:
                    error_msg = f"Invalid response format from Ollama: {result}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                
                # Extract content from assistant message
                assistant_message = result["message"]
                if assistant_message.get("role") != "assistant":
                    error_msg = f"Expected assistant role, got: {assistant_message.get('role')}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                
                generated_text = assistant_message.get("content", "").strip()
                
                # Clean up the response - remove markdown formatting if present
                generated_text = self._clean_code_response(generated_text)
                
                logger.info(f"Generated {len(generated_text)} characters of remediated code")
                return generated_text
                
        except httpx.TimeoutException:
            error_msg = "Timeout while communicating with Ollama service"
            logger.error(error_msg)
            raise Exception(error_msg)
        except httpx.RequestError as e:
            error_msg = f"Network error while communicating with Ollama: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
        except json.JSONDecodeError:
            error_msg = "Invalid JSON response from Ollama service"
            logger.error(error_msg)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Ollama client error: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def _clean_code_response(self, response: str) -> str:
        """
        Clean up the AI response to extract just the code.
        
        Args:
            response: Raw response from the AI model
            
        Returns:
            Cleaned code snippet
        """
        # Remove markdown code blocks if present
        lines = response.split('\n')
        cleaned_lines = []
        in_code_block = False
        
        for line in lines:
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            
            if in_code_block or not any(line.strip().startswith(prefix) for prefix in ['Here', 'This', 'The', 'Note:', 'Remember:', 'Example:']):
                cleaned_lines.append(line)
        
        cleaned_response = '\n'.join(cleaned_lines).strip()
        
        # If the response is empty after cleaning, return the original
        if not cleaned_response:
            return response.strip()
            
        return cleaned_response
    
    async def health_check(self) -> bool:
        """
        Check if Ollama service is available.
        
        Returns:
            True if service is available, False otherwise
        """
        try:
            # Test with a simple chat request
            url = f"{self.base_url}/api/chat"
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": "test"}],
                "stream": False
            }
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
                is_healthy = response.status_code == 200
                logger.debug(f"Ollama health check: {'healthy' if is_healthy else 'unhealthy'}")
                return is_healthy
        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return False
