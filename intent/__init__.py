"""
Intent-based security layer (Layer 0) for MCPCommerce.

This package implements Tenant-Scoped Intent Certificates (TSIC) to address
the gap in Paper 1: verifying "DID THE HUMAN ACTUALLY ASK FOR THIS?" in addition
to identity-based RBAC's "CAN this role do this?"

Layer 0 runs BEFORE Layers 1-10, blocking malicious/missing/expired/tampered
certificates before they reach the existing security stack.

Novel contribution (Paper 2):
- Tenant-scoped intent verification prevents cross-tenant data leakage
- Cross-tenant intent leakage detection (new attack class)
- Certificate replay prevention
- Intent drift detection
- Cumulative spend tracking across orders
"""

from .intent_certificate import (
    IntentCertificate,
    CertificateExpiredError,
    CertificateTamperedError,
    CertificateNotFoundError,
)
from .tenant_scope import (
    TenantScopeEnforcer,
    TenantScopeViolationError,
    SpendLimitExceededError,
    CrossTenantIntentLeakageError,
)
from .intent_middleware import (
    IntentMiddleware,
    IntentToolMismatchError,
    CertificateReplayError,
    IntentDriftWarning,
)
from .injection_scanner import (
    InjectionScanner,
    scan_tool_result,
)

__all__ = [
    # Main classes
    "IntentCertificate",
    "TenantScopeEnforcer",
    "IntentMiddleware",
    "InjectionScanner",

    # Convenience functions
    "scan_tool_result",

    # Certificate exceptions
    "CertificateExpiredError",
    "CertificateTamperedError",
    "CertificateNotFoundError",

    # Tenant scope exceptions
    "TenantScopeViolationError",
    "SpendLimitExceededError",
    "CrossTenantIntentLeakageError",

    # Middleware exceptions
    "IntentToolMismatchError",
    "CertificateReplayError",
    "IntentDriftWarning",
]
