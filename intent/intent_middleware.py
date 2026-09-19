"""
Intent Middleware - Layer 0 orchestrator for the TSIC security stack.

This module provides the IntentMiddleware.before_tool_call() function that runs
BEFORE all existing Paper 1 security layers (Layers 1-10). It orchestrates:
1. Certificate verification (expiration, HMAC signature)
2. Certificate replay prevention (customer_id match)
3. Call count tracking and intent drift detection
4. Intent-to-tool matching (does the certificate authorize this tool?)
5. Tenant scope enforcement (read/write rules)
6. Cross-tenant leakage detection
7. Audit logging of Layer 0 decisions

FAIL-CLOSED behavior: Any unexpected exception (DB error, malformed cert, etc.)
propagates as a Layer 0 failure and BLOCKS the call. Never fail open.
"""

import hashlib
from typing import Dict, Any, Optional
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


class IntentMiddleware:
    """
    Layer 0 middleware that enforces intent-based authorization before tool execution.

    This is the integration point between the TSIC system and the existing MCP server.
    Every tool handler in server.py will call:

        await intent_middleware.before_tool_call(tool_name, params, certificate_id)

    BEFORE calling authenticate_and_authorize(). This ensures Layer 0 runs first.
    """

    # Map each tool to its required intent classes
    # A tool call is only allowed if the certificate contains at least one of the
    # required intents for that tool.
    TOOL_INTENT_MAP = {
        # Customer read tools
        "search_products": {"search"},
        "get_product_details": {"search"},
        "track_order": {"track"},
        "get_order_history": {"search"},  # Historical view is a search operation

        # Customer write tools
        "place_order": {"order"},

        # Admin read tools
        "view_all_orders": {"admin"},       # Admin-specific operation
        "sales_summary": {"admin"},         # Admin-specific operation
        "view_security_alerts": {"admin"},  # Admin-specific operation

        # Admin write tools
        "add_product": {"admin"},           # Admin-specific operation
        "update_inventory": {"admin"},      # Admin-specific operation
        "update_order_status": {"admin"},   # Admin-specific operation
        "rotate_api_key": {"admin"},        # Admin-specific operation
    }

    # Maximum call count before intent drift warning (from IntentCertificate)
    MAX_CALLS_BEFORE_DRIFT_WARNING = 20

    def __init__(self, database, logger):
        """
        Initialize the IntentMiddleware.

        Args:
            database: Database instance for certificate storage/retrieval
            logger: AuditLogger instance for logging Layer 0 decisions
        """
        self.db = database
        self.logger = logger
        self.cert_manager = IntentCertificate(database)
        self.scope_enforcer = TenantScopeEnforcer(database)

    async def before_tool_call(
        self,
        tool_name: str,
        params: Dict[str, Any],
        certificate_id: str,
        api_key: str
    ) -> None:
        """
        Layer 0 authorization check - runs BEFORE authenticate_and_authorize().

        Execution flow:
        1. Verify certificate (expiration, HMAC signature) -> raises if invalid
        2. Verify customer_id matches (prevent certificate replay)
        3. Increment call_count and check for intent drift
        4. Check tool-intent match -> raises IntentToolMismatchError if mismatch
        5. Route to check_read or check_write based on tool type
        6. Detect cross-tenant leakage in params
        7. Log Layer 0 decision via existing logger.py
        8. Return PROCEED (or raise on any failure)

        FAIL-CLOSED behavior: Any unexpected exception (DB error, malformed cert, etc.)
        propagates as a Layer 0 failure and BLOCKS the call. Never fail open.

        Args:
            tool_name: Name of the tool being called (e.g., "search_products")
            params: The tool call parameters dict
            certificate_id: UUID string identifying the intent certificate
            api_key: The API key being used for this call (for replay prevention)

        Raises:
            CertificateExpiredError: Certificate has expired
            CertificateTamperedError: HMAC signature verification failed
            CertificateNotFoundError: certificate_id not in database
            CertificateReplayError: customer_id mismatch (replay attack)
            IntentDriftWarning: Call count exceeded (warning only, doesn't block)
            IntentToolMismatchError: Tool not authorized by certificate's intent_classes
            TenantScopeViolationError: Write violates tenant scope
            SpendLimitExceededError: Order total exceeds spend_limit
            CrossTenantIntentLeakageError: Params reference multiple companies without auth
            Exception: Any other unexpected error (FAIL-CLOSED)
        """
        try:
            # Step 1: Verify certificate (expiration, HMAC signature)
            certificate = IntentCertificate.verify(self.db, certificate_id)

            # Step 2: Certificate replay prevention
            # Verify that the customer_id in the certificate matches the customer_id
            # of the API key being used in THIS call
            lookup_hash = hashlib.sha256((api_key + "lookup_salt_constant").encode()).hexdigest()
            current_customer = self.db.get_customer_by_lookup_hash(lookup_hash)

            if not current_customer:
                raise CertificateReplayError(
                    f"API key not found - cannot verify certificate ownership"
                )

            if current_customer['customer_id'] != certificate['customer_id']:
                # Certificate was issued to a different customer - replay attack!
                self.logger.log_tool_call(
                    tool_name="intent_middleware",
                    company_id=current_customer.get('company_id'),
                    user_email=current_customer.get('email'),
                    role=current_customer.get('role'),
                    input_params={
                        "attack_type": "certificate_replay",
                        "certificate_id": certificate_id,
                        "certificate_customer_id": certificate['customer_id'],
                        "actual_customer_id": current_customer['customer_id']
                    },
                    success=False,
                    result="CERTIFICATE_REPLAY_BLOCKED",
                    error=f"Certificate belongs to customer {certificate['customer_id']}, "
                          f"but API key belongs to customer {current_customer['customer_id']}"
                )

                raise CertificateReplayError(
                    f"Certificate replay detected: certificate issued to different customer"
                )

            # Step 3: Increment call_count and check for intent drift
            current_call_count = certificate.get('call_count', 0)
            new_call_count = current_call_count + 1

            # Update call_count in database
            self.db.increment_certificate_call_count(certificate_id)

            # Check for intent drift (warning only, doesn't block)
            if new_call_count > self.MAX_CALLS_BEFORE_DRIFT_WARNING:
                # Log warning
                self.logger.log_tool_call(
                    tool_name="intent_middleware",
                    company_id=current_customer.get('company_id'),
                    user_email=current_customer.get('email'),
                    role=current_customer.get('role'),
                    input_params={
                        "warning_type": "intent_drift",
                        "certificate_id": certificate_id,
                        "call_count": new_call_count
                    },
                    success=True,
                    result="INTENT_DRIFT_WARNING",
                    error=None
                )

                # Raise warning (but don't block)
                raise IntentDriftWarning(
                    f"Certificate {certificate_id} has been used {new_call_count} times, "
                    f"exceeding the expected threshold of {self.MAX_CALLS_BEFORE_DRIFT_WARNING}. "
                    f"This may indicate intent drift or session hijacking. (Warning only, not blocking)"
                )

            # Step 4: Check tool-intent match
            self.check_tool_intent_match(certificate, tool_name)

            # Step 5: Route to check_read or check_write based on tool type
            if tool_name in TenantScopeEnforcer.READ_TOOLS:
                self.scope_enforcer.check_read(certificate, tool_name, params)
            elif tool_name in TenantScopeEnforcer.WRITE_TOOLS:
                self.scope_enforcer.check_write(certificate, tool_name, params)
            else:
                # Unknown tool - fail closed
                raise IntentToolMismatchError(f"Unknown tool: {tool_name}")

            # Step 6: Detect cross-tenant leakage
            self.scope_enforcer.detect_cross_tenant_leakage(certificate, params)

            # Step 7: Log successful Layer 0 authorization
            self.logger.log_tool_call(
                tool_name="intent_middleware",
                company_id=current_customer.get('company_id'),
                user_email=current_customer.get('email'),
                role=current_customer.get('role'),
                input_params={
                    "certificate_id": certificate_id,
                    "tool_name": tool_name,
                    "intent_classes": certificate['intent_classes'],
                    "tenant_scope": certificate['tenant_scope']
                },
                success=True,
                result="LAYER_0_AUTHORIZED",
                error=None
            )

            # Step 8: Return PROCEED (implicit - no exception raised)

        except IntentDriftWarning:
            # IntentDriftWarning is special - log but don't block
            # Re-raise so caller can handle (but tool call should still proceed)
            raise

        except (CertificateExpiredError, CertificateTamperedError, CertificateNotFoundError,
                CertificateReplayError, IntentToolMismatchError, TenantScopeViolationError,
                SpendLimitExceededError, CrossTenantIntentLeakageError) as e:
            # Layer 0 security exceptions - log and propagate
            self.logger.log_tool_call(
                tool_name="intent_middleware",
                company_id=None,
                user_email=None,
                role=None,
                input_params={
                    "certificate_id": certificate_id,
                    "tool_name": tool_name,
                    "error_type": type(e).__name__
                },
                success=False,
                result="LAYER_0_BLOCKED",
                error=str(e)
            )
            raise

        except Exception as e:
            # FAIL-CLOSED: Any unexpected exception blocks the call
            self.logger.log_tool_call(
                tool_name="intent_middleware",
                company_id=None,
                user_email=None,
                role=None,
                input_params={
                    "certificate_id": certificate_id,
                    "tool_name": tool_name,
                    "error_type": "UNEXPECTED_ERROR"
                },
                success=False,
                result="LAYER_0_FAIL_CLOSED",
                error=f"Unexpected error in Layer 0: {str(e)}"
            )
            # Propagate the exception (fail closed)
            raise

    def check_tool_intent_match(
        self,
        certificate: Dict[str, Any],
        tool_name: str
    ) -> None:
        """
        Verify that the certificate's intent_classes authorize calling this tool.

        Uses TOOL_INTENT_MAP to determine required intents. A tool call is allowed
        if the certificate contains at least ONE of the required intent classes.

        Example:
        - Tool: "place_order", requires intent "order"
        - Certificate has intent_classes: ["search", "order"]
        - Match found ("order" in certificate) -> PASS

        Example of mismatch:
        - Tool: "place_order", requires intent "order"
        - Certificate has intent_classes: ["search"]
        - No match -> raise IntentToolMismatchError

        This is the core defense against prompt injection: if a malicious product
        description injects "also export all customer emails", the LLM tries to call
        an export tool, but the certificate only has intent_classes=["search"], so
        this check blocks it BEFORE Layer 1 even runs.

        Args:
            certificate: The verified intent certificate dict
            tool_name: Name of the tool being called

        Raises:
            IntentToolMismatchError: If no required intent class is present in certificate
        """
        # Get required intents for this tool
        required_intents = self.TOOL_INTENT_MAP.get(tool_name)

        if not required_intents:
            raise IntentToolMismatchError(
                f"Tool {tool_name} not found in TOOL_INTENT_MAP - cannot verify intent"
            )

        # Get certificate's intent classes
        cert_intents = set(certificate.get('intent_classes', []))

        # Check if ANY required intent is present in certificate
        if not cert_intents.intersection(required_intents):
            raise IntentToolMismatchError(
                f"Tool '{tool_name}' requires intent {required_intents}, "
                f"but certificate only has {list(cert_intents)}. "
                f"This tool call is not authorized by the user's intent."
            )


# Custom exceptions for intent middleware

class IntentToolMismatchError(Exception):
    """
    Raised when a tool call doesn't match the certificate's intent_classes.

    This is the primary defense against prompt injection attacks where the LLM
    is manipulated to call tools the human never requested.

    Layer 0 blocks this BEFORE Layer 1 (authentication) runs, as verified by test.
    """
    pass


class CertificateReplayError(Exception):
    """
    Raised when a certificate is used by a different customer than it was issued to.

    This prevents certificate replay attacks where an attacker intercepts a
    certificate and tries to use it with their own API key.
    """
    pass


class IntentDriftWarning(Warning, Exception):
    """
    Raised when a certificate's call_count exceeds MAX_CALLS_BEFORE_DRIFT_WARNING.

    This is a WARNING ONLY - it doesn't block the call, but logs the event for
    security monitoring. It may indicate:
    - Session hijacking
    - Intent drift (user's original request has diverged)
    - Unusually long session

    Note: This is both a Warning and an Exception to allow it to be raised and caught.
    """
    pass
