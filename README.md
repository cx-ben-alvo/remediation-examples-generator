# Code Remediation API Service

A professional Python REST API service that provides AI-powered code remediation with security scanning validation.

## Features

- **AI-Powered Remediation**: Uses Ollama with Llama3.2 to generate secure code fixes
- **Security Validation**: Scans generated code with Vorpal security scanner
- **Retry Logic**: Automatically retries up to 5 times if vulnerabilities are found
- **Multi-Language Support**: Supports Python, JavaScript, Java, Go, and C#
- **Professional Architecture**: Follows Python best practices with proper separation of concerns
- **Comprehensive Testing**: Full test suite with pytest and mocking
- **Configuration Management**: Environment-based configuration with Pydantic
- **Production Ready**: Proper logging, error handling, and monitoring

## Prerequisites

### Option 1: Docker (Recommended)

- Docker and Docker Compose installed on your system
- No other prerequisites needed! Everything is containerized.

### Option 2: Local Installation

1. **Ollama Service**: Make sure Ollama is running at `127.0.0.1:11434`
   ```bash
   # Install Ollama if not already installed
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Pull the Llama3.2 model
   ollama pull llama3.2
   
   # Start Ollama service
   ollama serve
   ```

2. **Python 3.8+**: Required for running the API service

## Project Structure

```
remediation/
├── src/
│   └── remediation/
│       ├── __init__.py
│       ├── main.py              # Application entry point
│       ├── api/
│       │   ├── __init__.py
│       │   └── routes.py        # API endpoints
│       ├── services/
│       │   ├── __init__.py
│       │   ├── ollama_client.py # Ollama AI integration
│       │   └── vorpal_scanner.py # Security scanner
│       ├── models/
│       │   ├── __init__.py
│       │   └── schemas.py       # Pydantic models
│       └── config/
│           ├── __init__.py
│           └── settings.py      # Configuration management
├── tests/                       # Comprehensive test suite
├── scripts/                     # Utility scripts
├── docs/                        # Documentation
├── resources/                   # External tools (Vorpal)
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
├── setup.py                     # Package setup
├── pyproject.toml              # Modern Python packaging
├── .env.example                # Environment configuration template
└── README.md
```

## Installation

### Option 1: Docker Installation (Recommended)

1. Clone this repository and navigate to the project directory:
   ```bash
   cd remediation
   ```

2. Start the services using Docker Compose:
   ```bash
   docker-compose up -d
   ```
   This will:
   - Build the remediation service image
   - Pull and start the Ollama service
   - Set up networking between services
   - Configure health checks
   - Mount necessary volumes for Ollama models

3. The services will be available at:
   - Remediation API: http://localhost:8000
   - Ollama Service: http://localhost:11434

4. To view logs:
   ```bash
   # View all logs
   docker-compose logs -f

   # View specific service logs
   docker-compose logs -f remediation-api
   docker-compose logs -f ollama-service
   ```

5. To stop the services:
   ```bash
   docker-compose down
   ```

### Option 2: Local Development Installation

1. Clone this repository and navigate to the project directory:
   ```bash
   cd remediation
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Create environment configuration:
   ```bash
   cp .env.example .env
   # Edit .env file as needed
   ```

### Production Installation

1. Install the package:
   ```bash
   pip install -e .
   ```

2. Or install from requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Service

### Using the new structure:

```bash
# From project root
python -m src.remediation.main

# Or using the convenience script
./scripts/start.sh
```

### Using uvicorn directly:

```bash
uvicorn src.remediation.main:app --host 0.0.0.0 --port 8000 --reload
```

The service will be available at `http://localhost:8000`

## API Usage

### Endpoint: `POST /api/remediation`

**Request Body:**
```json
{
  "language": "go",
  "ruleName": "Unsafe SQL Query Construction", 
  "description": "Dynamically constructing SQL queries through string concatenation can lead to SQL injection vulnerabilities...",
  "remediationAdvice": "Consider using parameterized queries with SqlCommand and not concatenate strings to form SQL queries."
}
```

**Response:**
```json
{
  "remediated_code": "query: `SELECT id, username, email, role FROM users WHERE username = ? AND password = ?`,\n        params: [username, password],"
}
```

### Example using curl:

```bash
curl -X POST "http://localhost:8000/api/remediation" \
  -H "Content-Type: application/json" \
  -d '{
    "language": "go",
    "ruleName": "Unsafe SQL Query Construction",
    "description": "Dynamically constructing SQL queries through string concatenation can lead to SQL injection vulnerabilities, allowing attackers to manipulate queries and execute arbitrary commands.",
    "remediationAdvice": "Consider using parameterized queries with SqlCommand and not concatenate strings to form SQL queries."
  }'
```

### Example using the provided script:

```bash
python scripts/example_request.py
```

## How It Works

1. **Receive Request**: API receives vulnerability details in the request body
2. **AI Generation**: Sends request to Ollama service with security expert prompt
3. **Security Scanning**: Scans generated code with Vorpal security scanner
4. **Validation Loop**: If vulnerabilities found, retries with conversation history (max 5 attempts)
5. **Return Result**: Returns secure code snippet or error after max retries

## Health Check

Check service health:
```bash
curl http://localhost:8000/health
```

## Supported Languages

- Python (.py)
- JavaScript (.js)
- Java (.java)
- Go (.go)
- C# (.cs)

## Error Handling

The service includes comprehensive error handling:
- **422 Unprocessable Entity**: Unable to generate secure code after 5 attempts
- **500 Internal Server Error**: Service errors (Ollama unavailable, Vorpal scanner issues, etc.)

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest -m unit
pytest -m integration
```

### Code Quality

```bash
# Format code
black src tests

# Sort imports
isort src tests

# Lint code
flake8 src tests

# Type checking
mypy src
```

### Environment Configuration

The service uses environment variables for configuration. Copy `.env.example` to `.env` and modify as needed:

```bash
# API Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Ollama Configuration
OLLAMA_HOST=127.0.0.1
OLLAMA_PORT=11434
OLLAMA_MODEL=llama3.2

# Scanner Configuration
VORPAL_PATH=./resources/vorpal_cli_darwin_arm64
MAX_RETRIES=5
```

## Documentation

- 📊 **[Architecture Diagram](docs/architecture-diagram.md)** - Detailed system architecture and component relationships
- 🔄 **[Sequence Diagram](docs/sequence-diagram.md)** - Complete API request flow with retry logic

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Ollama        │    │   Vorpal        │
│   REST API      │───▶│   AI Service    │    │   Scanner       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        │                        ▼                        │
        │              ┌─────────────────┐                │
        │              │  Generated      │                │
        │              │  Code           │                │
        │              └─────────────────┘                │
        │                        │                        │
        │                        ▼                        │
        └──────────────────────────────────────────────────┘
                                 │
                                 ▼
                      ┌─────────────────┐
                      │  Security       │
                      │  Validation     │
                      └─────────────────┘
```

For detailed architecture and flow diagrams, see the [documentation section](#documentation) above.

### Component Overview

- **API Layer** (`src/remediation/api/`): FastAPI routes and request handling
- **Services Layer** (`src/remediation/services/`): External service integrations
- **Models Layer** (`src/remediation/models/`): Data models and validation
- **Configuration Layer** (`src/remediation/config/`): Settings management
- **Tests** (`tests/`): Comprehensive test suite with mocking

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the coding standards
4. Add tests for your changes
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 