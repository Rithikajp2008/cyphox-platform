"""
API package for Recovery REST API
"""
from .recovery_routes import router as recovery_router

__all__ = ["recovery_router"]
