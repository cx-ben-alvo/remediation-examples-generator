# Code Remediation API - Sequence Diagram

This sequence diagram shows the complete flow of the code remediation API, including the retry logic for security validation.

```mermaid
sequenceDiagram
    participant Client
    participant API as "FastAPI Routes"
    participant Ollama as "Ollama Client"
    participant Vorpal as "Vorpal Scanner"
    participant Config as "Settings"

    Client->>API: POST /api/remediation<br/>{language, ruleName, description, remediationAdvice}
    
    API->>Config: Get max_retries, allowed_languages
    Config-->>API: Configuration values
    
    API->>API: Validate language support
    
    note over API: Retry Loop (max 5 attempts)
    loop Max Retries (5)
        API->>API: Build prompt with system instructions<br/>+ user request + conversation history
        
        API->>Ollama: generate_remediation(prompt)
        Ollama->>Ollama: Generate code using Llama3.2<br/>with low temperature (0.1)
        Ollama-->>API: Generated code snippet
        
        API->>API: Validate non-empty response
        
        API->>Vorpal: scan_code(code, language, filename)
        Vorpal->>Vorpal: Execute security scan<br/>on generated code
        Vorpal-->>API: Scan results
        
        alt No Vulnerabilities Found
            API-->>Client: 200 OK<br/>{remediated_code}
        else Vulnerabilities Found
            API->>API: Add vulnerability details<br/>to conversation history
            note over API: Continue to next attempt<br/>with enhanced context
        end
    end
    
    alt After Max Retries with Vulnerabilities
        API-->>Client: 422 Unprocessable Entity<br/>{"Unable to generate secure code"}
    else Service Error
        API-->>Client: 500 Internal Server Error<br/>{"Service error details"}
    end
```

## Key Flow Points

1. **Request Validation**: The API first validates that the requested programming language is supported
2. **Iterative Improvement**: If vulnerabilities are found, the system uses conversation history to provide context for better code generation
3. **Security-First Approach**: Every generated code snippet is scanned before being returned to the client
4. **Graceful Degradation**: Clear error responses with details about what went wrong
5. **Configurable Retries**: Maximum retry attempts are configurable via environment settings

