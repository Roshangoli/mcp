"""
Injection Scanner module - detects prompt injection attempts in tool results.

This module scans product descriptions and other user-generated content for
patterns that indicate prompt injection attempts. When detected, the content
is sanitized and the attempt is logged, but the tool call continues with
sanitized results rather than blocking entirely.

This runs AFTER the database query but BEFORE returning results to Claude,
providing defense-in-depth against indirect prompt injection via data.
"""

import re
from typing import List, Dict, Any, Optional


class InjectionScanner:
    """
    Scans tool results for prompt injection patterns and sanitizes them.

    The scanner looks for common injection keywords and phrases that attempt
    to manipulate the LLM's behavior, such as:
    - "ignore previous instructions"
    - "you are now"
    - "system prompt"
    - "disregard"

    When found, the description is replaced with a warning flag and the
    attempt is logged for security monitoring.
    """

    # Prompt injection detection patterns
    # These are common phrases used in indirect prompt injection attacks
    INJECTION_PATTERNS = [
        # Ignore/disregard patterns
        r'\bignore\b.*\bprevious\b',
        r'\bignore\b.*\binstructions?\b',
        r'\bignore\s+your\b',
        r'\bdisregard\b',
        r'\bforget\b.*\beverything\b',
        r'\bforget\b.*\binstructions?\b',

        # Override/replacement patterns
        r'\bnew\s+instructions?\b',
        r'\binstead\s+do\b',
        r'\boverride\b',
        r'\breplace\b.*\binstructions?\b',

        # System/role manipulation patterns
        r'\bsystem\s+prompt\b',
        r'\byou\s+are\s+now\b',
        r'\bact\s+as\b',
        r'\bpretend\s+to\s+be\b',
        r'\brole\s*:\s*system\b',

        # Data exfiltration patterns
        r'\bexport\s+all\b',
        r'\bsend\s+all\b',
        r'\bget\s+all\b.*\b(emails?|customers?|data|records?)\b',
        r'\bdump\s+(database|data|records?)\b',

        # Jailbreak patterns
        r'\bDAN\s+mode\b',
        r'\bjailbreak\b',
        r'\bdeveloper\s+mode\b',
    ]

    # Compiled regex patterns for performance
    _compiled_patterns: Optional[List[re.Pattern]] = None

    @classmethod
    def _get_compiled_patterns(cls) -> List[re.Pattern]:
        """Lazy-compile regex patterns on first use."""
        if cls._compiled_patterns is None:
            cls._compiled_patterns = [
                re.compile(pattern, re.IGNORECASE) for pattern in cls.INJECTION_PATTERNS
            ]
        return cls._compiled_patterns

    @classmethod
    def scan_for_injected_instructions(
        cls,
        tool_result: Any,
        logger: Optional[Any] = None
    ) -> Any:
        """
        Scan tool results for prompt injection attempts and sanitize them.

        This function scans product descriptions and other text fields in tool
        results for injection patterns. When found:
        1. Log the attempt (if logger provided)
        2. Replace the description with "[CONTENT FLAGGED - INJECTION ATTEMPT DETECTED]"
        3. Continue returning the product but sanitized

        This approach allows the tool to function while neutralizing the injection.

        Args:
            tool_result: The result from a tool call (can be dict, list, or string)
            logger: Optional AuditLogger instance for logging injection attempts

        Returns:
            Sanitized tool result with injection attempts flagged
        """
        # Handle different result types
        if isinstance(tool_result, list):
            return [cls._scan_item(item, logger) for item in tool_result]
        elif isinstance(tool_result, dict):
            return cls._scan_item(tool_result, logger)
        else:
            # For strings or other types, scan directly
            return cls._scan_text(str(tool_result), logger)

    @classmethod
    def _scan_item(cls, item: Dict[str, Any], logger: Optional[Any] = None) -> Dict[str, Any]:
        """
        Scan a single dictionary item (e.g., product record) for injection attempts.

        Focuses on description fields which are most likely to contain
        user-generated content that could be exploited for injection.

        Args:
            item: Dict representing a product, order, or other entity
            logger: Optional AuditLogger instance

        Returns:
            Sanitized item dict
        """
        if not isinstance(item, dict):
            return item

        # Create a copy to avoid mutating the original
        sanitized = item.copy()

        # Scan description field (most common injection vector)
        if 'description' in sanitized and isinstance(sanitized['description'], str):
            original_desc = sanitized['description']
            is_injected, matched_pattern = cls._check_for_injection(original_desc)

            if is_injected:
                # Log the injection attempt
                if logger:
                    cls._log_injection_attempt(
                        logger,
                        item.get('product_id') or item.get('order_id') or item.get('customer_id'),
                        original_desc,
                        matched_pattern
                    )

                # Replace with flagged content
                sanitized['description'] = "[CONTENT FLAGGED - INJECTION ATTEMPT DETECTED]"

        # Scan other potential text fields
        text_fields = ['name', 'category', 'notes', 'comments']
        for field in text_fields:
            if field in sanitized and isinstance(sanitized[field], str):
                original_text = sanitized[field]
                is_injected, matched_pattern = cls._check_for_injection(original_text)

                if is_injected:
                    if logger:
                        cls._log_injection_attempt(
                            logger,
                            item.get('product_id') or item.get('order_id') or item.get('customer_id'),
                            original_text,
                            matched_pattern
                        )
                    sanitized[field] = "[CONTENT FLAGGED - INJECTION ATTEMPT DETECTED]"

        return sanitized

    @classmethod
    def _scan_text(cls, text: str, logger: Optional[Any] = None) -> str:
        """
        Scan plain text for injection attempts.

        Args:
            text: Text to scan
            logger: Optional AuditLogger instance

        Returns:
            Sanitized text or original if no injection detected
        """
        is_injected, matched_pattern = cls._check_for_injection(text)

        if is_injected:
            if logger:
                cls._log_injection_attempt(logger, None, text, matched_pattern)
            return "[CONTENT FLAGGED - INJECTION ATTEMPT DETECTED]"

        return text

    @classmethod
    def _check_for_injection(cls, text: str) -> tuple[bool, Optional[str]]:
        """
        Check if text contains injection patterns.

        Args:
            text: Text to check

        Returns:
            Tuple of (is_injected: bool, matched_pattern: str or None)
        """
        if not text or not isinstance(text, str):
            return False, None

        patterns = cls._get_compiled_patterns()

        for pattern in patterns:
            match = pattern.search(text)
            if match:
                # Return True and the matched pattern for logging
                return True, pattern.pattern

        return False, None

    @classmethod
    def _log_injection_attempt(
        cls,
        logger: Any,
        entity_id: Optional[int],
        original_content: str,
        matched_pattern: str
    ) -> None:
        """
        Log a detected injection attempt via the audit logger.

        Args:
            logger: AuditLogger instance
            entity_id: Optional ID of the entity containing the injection (product_id, etc.)
            original_content: The original content that contained the injection
            matched_pattern: The regex pattern that matched
        """
        try:
            # Log as a security event
            # Truncate original content for logging (don't log full injection payload)
            truncated_content = original_content[:200] + "..." if len(original_content) > 200 else original_content

            logger.log_tool_call(
                tool_name="injection_scanner",
                company_id=None,
                user_email=None,
                role=None,
                input_params={
                    "entity_id": entity_id,
                    "matched_pattern": matched_pattern,
                    "content_preview": truncated_content
                },
                success=True,
                result="INJECTION_ATTEMPT_DETECTED_AND_SANITIZED",
                error=None
            )
        except Exception:
            # Don't fail the tool call if logging fails
            pass


def scan_tool_result(tool_result: Any, logger: Optional[Any] = None) -> Any:
    """
    Convenience function to scan tool results for injection attempts.

    This is the main entry point for using the injection scanner in tool handlers.

    Usage in server.py:
        products = db.search_products(...)
        products = scan_tool_result(products, audit_logger)
        return [TextContent(type="text", text=json.dumps(products))]

    Args:
        tool_result: The result to scan (dict, list, or string)
        logger: Optional AuditLogger instance

    Returns:
        Sanitized result
    """
    return InjectionScanner.scan_for_injected_instructions(tool_result, logger)
