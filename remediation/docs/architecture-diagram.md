# Code Remediation API - Architecture Diagram

This architecture diagram shows the complete system structure, including all layers and components of the code remediation service.

```mermaid
graph TB
    subgraph "Client Layer"
        Client[Client Applications]
        Scripts[Example Scripts]
    end
    
    subgraph "API Layer"
        FastAPI[FastAPI Application]
        Routes[API Routes]
        Health[Health Check]
    end
    
    subgraph "Service Layer"
        OllamaClient[Ollama Client]
        VorpalScanner[Vorpal Scanner]
    end
    
    subgraph "External Services"
        OllamaService[Ollama AI Service<br/>Llama3.2 Model]
        VorpalCLI[Vorpal CLI Scanner<br/>Security Analysis]
    end
    
    subgraph "Configuration & Models"
        Settings[Settings<br/>Environment Config]
        Schemas[Pydantic Schemas<br/>Request/Response Models]
    end
    
    subgraph "Infrastructure"
        Logging[Logging System]
        ErrorHandling[Error Handling]
        DependencyInjection[Dependency Injection]
    end
    
    %% Client connections
    Client --> FastAPI
    Scripts --> FastAPI
    
    %% API Layer connections
    FastAPI --> Routes
    FastAPI --> Health
    Routes --> OllamaClient
    Routes --> VorpalScanner
    
    %% Service Layer connections
    OllamaClient --> OllamaService
    VorpalScanner --> VorpalCLI
    
    %% Configuration connections
    Routes --> Settings
    Routes --> Schemas
    OllamaClient --> Settings
    VorpalScanner --> Settings
    
    %% Infrastructure connections
    Routes --> Logging
    Routes --> ErrorHandling
    FastAPI --> DependencyInjection
    
    %% Styling
    classDef clientLayer fill:#e1f5fe
    classDef apiLayer fill:#f3e5f5
    classDef serviceLayer fill:#e8f5e8
    classDef externalLayer fill:#fff3e0
    classDef configLayer fill:#fce4ec
    classDef infraLayer fill:#f1f8e9
    
    class Client,Scripts clientLayer
    class FastAPI,Routes,Health apiLayer
    class OllamaClient,VorpalScanner serviceLayer
    class OllamaService,VorpalCLI externalLayer
    class Settings,Schemas configLayer
    class Logging,ErrorHandling,DependencyInjection infraLayer
```

## Architecture Layers

### Client Layer
- **Client Applications**: External applications consuming the remediation API
- **Example Scripts**: Provided testing and demonstration scripts

### API Layer
- **FastAPI Application**: Main web application framework
- **API Routes**: RESTful endpoints for remediation and health checking
- **Health Check**: Service availability and dependency status monitoring

### Service Layer
- **Ollama Client**: Abstraction layer for AI service communication
- **Vorpal Scanner**: Security scanning service wrapper

### External Services
- **Ollama AI Service**: AI model (Llama3.2) for code generation
- **Vorpal CLI Scanner**: External security vulnerability scanner

### Configuration & Models
- **Settings**: Environment-based configuration management with Pydantic
- **Schemas**: Request/response models and data validation

### Infrastructure
- **Logging System**: Comprehensive logging for monitoring and debugging
- **Error Handling**: Centralized error management and user-friendly responses
- **Dependency Injection**: FastAPI's dependency system for service management

## Design Principles

1. **Separation of Concerns**: Clear boundaries between API, business logic, and external services
2. **Dependency Injection**: Loose coupling through FastAPI's dependency system
3. **Configuration Management**: Environment-driven configuration for different deployment scenarios
4. **Error Handling**: Graceful error responses with appropriate HTTP status codes
5. **Security First**: Every code generation is validated through security scanning
6. **Observability**: Comprehensive logging for monitoring and troubleshooting

