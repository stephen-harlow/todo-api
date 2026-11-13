"""Credential-safe client for the native Vikunja v2 API.

The bot credentials live in one set of environment variables (``TODO_API_URL``,
``TODO_API_TOKEN[_FILE]``, and optional ``TODO_CF_ACCESS_CLIENT_ID[_FILE]`` /
``TODO_CF_ACCESS_CLIENT_SECRET[_FILE]``) so every tool talks to Vikunja the same
way and secrets are rotated in one place.
"""
from __future__ import annotations

from .client import (
    TaskResult,
    TodoAPIConfig,
    TodoAPIError,
    TodoConflictError,
    TodoWriteUncertainError,
    VikunjaClient,
    _NoRedirect,
)

__all__ = [
    "TaskResult",
    "TodoAPIConfig",
    "TodoAPIError",
    "TodoConflictError",
    "TodoWriteUncertainError",
    "VikunjaClient",
]
