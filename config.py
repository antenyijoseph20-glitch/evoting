"""
config.py - Centralized Configuration & Domain Constants
"""
from typing import Set

ALLOWED_CANDIDATES: Set[str] = {"APC", "LP", "PDP", "NNPP"}
SESSION_TTL_SECONDS: int = 900  # Sessions expire after 15 minutes
DEFAULT_RSA_KEY_SIZE: int = 1024