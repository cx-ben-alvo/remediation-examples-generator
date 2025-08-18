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
            error_msg = f"Timeout while communicating with Ollama service at {self.base_url}"
            logger.error(error_msg)
            logger.info("This may indicate the model is not loaded or the request is taking too long")
            raise Exception(error_msg)
        except httpx.ConnectError as e:
            error_msg = f"Cannot connect to Ollama service at {self.base_url}"
            logger.error(error_msg)
            logger.info("Make sure Ollama is running locally: ollama serve")
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
    
    async def check_model_availability(self) -> bool:
        """
        Check if the specified model is available in the local Ollama instance.
        
        Returns:
            True if model is available, False otherwise
        """
        try:
            url = f"{self.base_url}/api/tags"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    models_data = response.json()
                    available_models = [model["name"] for model in models_data.get("models", [])]
                    model_available = any(self.model in model_name for model_name in available_models)
                    
                    if not model_available:
                        logger.warning(f"Model '{self.model}' not found. Available models: {available_models}")
                        logger.info(f"To install the model, run: ollama pull {self.model}")
                    
                    return model_available
                return False
        except Exception as e:
            logger.warning(f"Failed to check model availability: {e}")
            return False

    async def health_check(self) -> bool:
        """
        Check if Ollama service is available and model is installed.
        
        Returns:
            True if service is available, False otherwise
        """
        try:
            # First check if Ollama service is running
            url = f"{self.base_url}/api/version"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    logger.warning(f"Ollama service not accessible at {self.base_url}")
                    logger.info("Make sure Ollama is running locally: ollama serve")
                    return False
                
                logger.debug(f"Ollama service running at {self.base_url}")
                
                # Check if model is available
                model_available = await self.check_model_availability()
                if not model_available:
                    logger.warning(f"Model '{self.model}' not available")
                    return False
                
                # Test with a simple chat request
                chat_url = f"{self.base_url}/api/chat"
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": "test"}],
                    "stream": False
                }
                
                response = await client.post(chat_url, json=payload)
                is_healthy = response.status_code == 200
                logger.debug(f"Ollama health check: {'healthy' if is_healthy else 'unhealthy'}")
                return is_healthy
                
        except httpx.ConnectError as e:
            logger.warning(f"Cannot connect to Ollama at {self.base_url}")
            logger.info("Make sure Ollama is running locally: ollama serve")
            return False
        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return False
