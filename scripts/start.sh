#!/bin/bash

# Code Remediation API Service Startup Script

echo "🚀 Starting Code Remediation API Service..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if Ollama is running
echo "🔍 Checking Ollama service..."
if ! curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
    echo "⚠️  Ollama service is not running at 127.0.0.1:11434"
    echo "   Please start Ollama service first:"
    echo "   ollama serve"
    echo ""
    echo "   And make sure llama3.2 model is available:"
    echo "   ollama pull llama3.2"
    exit 1
fi

# Check if required model is available
echo "🔍 Checking Llama3.2 model..."
if ! curl -s http://127.0.0.1:11434/api/tags | grep -q "llama3.2"; then
    echo "⚠️  Llama3.2 model not found. Pulling model..."
    ollama pull llama3.2
fi

# Check if dependencies are installed
if [ ! -d "venv" ] && [ ! -f ".requirements_installed" ]; then
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
    touch .requirements_installed
fi

# Check if Vorpal scanner is executable
if [ ! -x "resources/vorpal_cli_darwin_arm64" ]; then
    echo "⚠️  Making Vorpal scanner executable..."
    chmod +x resources/vorpal_cli_darwin_arm64
fi

echo "✅ All checks passed!"
echo "🌟 Starting Code Remediation API on http://localhost:8000"
echo ""
echo "📚 API Documentation: http://localhost:8000/docs"
echo "❤️  Health Check: http://localhost:8000/health"
echo ""
echo "Press Ctrl+C to stop the service"
echo ""

# Start the service using the new structure
python3 -m src.remediation.main 