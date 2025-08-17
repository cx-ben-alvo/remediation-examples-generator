"""Main application entry point"""

import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router
from .config.settings import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("app.log")
    ]
)

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI-powered code remediation with security validation",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API routes
    app.include_router(router)
    
    @app.on_event("startup")
    async def startup_event():
        """Application startup event"""
        logger.info(f"Starting {settings.app_name} v{settings.app_version}")
        logger.info(f"Ollama endpoint: {settings.ollama_base_url}")
        logger.info(f"Vorpal path: {settings.vorpal_path}")
        logger.info(f"Max retries: {settings.max_retries}")
        logger.info(f"Supported languages: {', '.join(settings.allowed_languages)}")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Application shutdown event"""
        logger.info("Shutting down Code Remediation Service")
    
    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting server on {settings.host}:{settings.port}")
    uvicorn.run(
        "src.remediation.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug"
    )
