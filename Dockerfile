# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements files first to leverage Docker cache
COPY requirements.txt .
COPY requirements-dev.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Copy vorpal binary to standard container path and make it executable
COPY resources/vorpal_cli_darwin_arm64 /usr/local/bin/vorpal
RUN chmod +x /usr/local/bin/vorpal

# Install the package in development mode
RUN pip install -e .

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "src.remediation.main:app", "--host", "0.0.0.0", "--port", "8000"]
