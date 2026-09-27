"""API error type mapped to a stable JSON envelope."""
from __future__ import annotations


class ApiError(Exception):
    """Business error rendered as {"error": {code, message, details}}."""

    def __init__(self, status_code: int, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


def conflict(code: str, message: str, details: dict | None = None) -> ApiError:
    return ApiError(409, code, message, details)
