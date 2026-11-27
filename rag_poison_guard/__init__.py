"""rag-poison-guard: scan RAG documents for poisoning and hidden-content risk."""

from .core import (
    DEFAULT_EXTENSIONS,
    FIXES,
    Finding,
    VERSION,
    iter_documents,
    risk_score,
    scan_corpus,
    scan_document,
    scan_text,
    summarize,
    verdict_for,
)

__version__ = VERSION
__all__ = [
    "DEFAULT_EXTENSIONS",
    "FIXES",
    "Finding",
    "VERSION",
    "iter_documents",
    "risk_score",
    "scan_corpus",
    "scan_document",
    "scan_text",
    "summarize",
    "verdict_for",
    "__version__",
]
