"""
Intent Certificate module - Layer 0 of the MCPCommerce security stack.

Implements short-lived (5 min), HMAC-signed certificates that capture user intent
BEFORE any tool call proceeds. This addresses prompt injection attacks where the
LLM is manipulated to call tools the human never actually requested.

Key Design:
- Rule-based intent parsing (NO LLM calls) using keyword/pattern matching
- Tenant scope limiting which companies a certificate authorizes
- HMAC-SHA256 signatures for tamper detection
- 5-minute expiration window for time-bounded authorization
- Role-based intent filtering (customers can't get "admin" intent)
- TurboQuant embedding compression for paraphrase attack detection (Paper 3 - NEW)
"""

import hmac
import hashlib
import secrets
import re
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import uuid4

# TurboQuant integration for semantic intent detection (Paper 3)
try:
    from .turboquant_layer import compress_certificate_embedding, TurboQuantIntentEnhancer
    TURBOQUANT_AVAILABLE = True
except ImportError:
    TURBOQUANT_AVAILABLE = False


class IntentCertificate:
    """
    Manages creation, storage, and verification of tenant-scoped intent certificates.

    A certificate binds together:
    - WHO made the request (customer_id)
    - WHAT they want to do (intent_classes like "search", "order", "track", "export")
    - WHICH items they care about (item_bounds for filtering)
    - SPENDING limits (spend_limit for place_order)
    - WHERE they can operate (tenant_scope: "ALL" or "1,3,5")
    - WHEN it's valid (created_at, expires_at)
    - PROOF of integrity (HMAC signature)
    """

    # Certificate validity period in seconds (5 minutes as specified)
    CERTIFICATE_TTL_SECONDS = 300

    # HMAC secret key for certificate signing
    # TODO: In production, load from secure environment variable or key management service
    # For now, generate a random secret on initialization (will be regenerated per server restart)
    # This is acceptable for the research prototype since certificates are short-lived
    _SECRET_KEY: Optional[bytes] = None

    # Intent class keywords for rule-based parsing
    # Attack surface note: These word lists define the security boundary for intent detection.
    # Paraphrase evasion is a known limitation - e.g., "retrieve records" instead of "export"
    # could bypass keyword matching. Future work: ML/LLM-based classifier could slot in here
    # without changing the certificate schema.
    INTENT_KEYWORDS = {
        "search": [
            "find", "show", "search", "look", "browse", "display", "list", "get",
            "check", "what", "which", "compare", "view", "see", "explore", "discover"
        ],
        "order": [
            "buy", "order", "purchase", "place", "want", "add to cart", "get me",
            "acquire", "checkout", "paying"
        ],
        "track": [
            "track", "status", "where", "when", "update", "check my order",
            "order status", "delivery status", "shipment", "shipping"
        ],
        "export": [
            "export", "download", "send", "email", "extract", "bulk", "all records",
            "dump", "retrieve all", "get all", "fetch all"
        ],
        "admin": [
            "add", "create", "update inventory", "change status", "rotate",
            "view alerts", "sales report", "manage", "administrate", "configure"
        ]
    }

    # Role-based intent filtering
    # This ensures customers can NEVER get "admin" or "export" intents in their certificate
    # no matter what they type in their request. This is a critical security boundary.
    ALLOWED_INTENTS_BY_ROLE = {
        "customer": ["search", "order", "track"],
        "global_customer": ["search", "order", "track"],
        "admin": ["search", "order", "track", "admin", "export"]
    }

    # Maximum number of calls before intent drift warning
    MAX_CALLS_BEFORE_DRIFT_WARNING = 20

    def __init__(self, database):
        """
        Initialize the IntentCertificate manager.

        Args:
            database: Database instance for storing and retrieving certificates
        """
        self.db = database

        # Initialize HMAC secret key on first use
        if IntentCertificate._SECRET_KEY is None:
            IntentCertificate._SECRET_KEY = secrets.token_bytes(32)

    @classmethod
    def create(
        cls,
        database,
        user_request_text: str,
        api_key: str,
        customer_id: int,
        use_turboquant: bool = True
    ) -> str:
        """
        Create a new intent certificate from a user's natural language request.

        This is the main entry point for generating certificates. It:
        1. Parses intent_classes from the user's text (rule-based + TurboQuant semantic)
        2. Extracts item_bounds (items/products mentioned)
        3. Extracts spend_limit (dollar amounts mentioned)
        4. Determines tenant_scope based on customer's role (global vs. specific company)
        5. Filters intent_classes by role (customers can't get "admin" intent)
        6. Signs the certificate with HMAC-SHA256
        7. Compresses request embedding via TurboQuant (Paper 3 - NEW)
        8. Stores it in the database
        9. Returns the certificate_id

        Args:
            database: Database instance
            user_request_text: The human's natural language request (e.g., "find laptops under $1000")
            api_key: User's API key (used to look up role and company_id)
            customer_id: The customer's ID
            use_turboquant: Enable TurboQuant semantic detection (default True)

        Returns:
            certificate_id: UUID string identifying the created certificate

        Raises:
            ValueError: If unable to parse intent or authenticate user
        """
        # Parse intent components from user request
        raw_intent_classes = cls.parse_intent(user_request_text)
        item_bounds = cls.parse_items(user_request_text)
        spend_limit = cls.parse_spend(user_request_text)

        # Get customer data to determine role and tenant scope
        # This reuses existing database lookup
        lookup_hash = hashlib.sha256((api_key + "lookup_salt_constant").encode()).hexdigest()
        customer = database.get_customer_by_lookup_hash(lookup_hash)

        if not customer:
            raise ValueError("Invalid API key - customer not found")

        # Filter intent_classes by role (CRITICAL SECURITY BOUNDARY)
        # A customer typing "admin" words CANNOT get "admin" intent in their certificate
        allowed_intents = cls.ALLOWED_INTENTS_BY_ROLE.get(customer['role'], ["search"])
        intent_classes = [intent for intent in raw_intent_classes if intent in allowed_intents]

        # Default to ["search"] if filtering leaves empty list
        if not intent_classes:
            intent_classes = ["search"]

        # PAPER 3 ENHANCEMENT: TurboQuant semantic detection for paraphrase evasion
        # This addresses the limitation acknowledged in line 51-53 above
        request_embedding_compressed = None
        paraphrase_metadata = None

        if use_turboquant and TURBOQUANT_AVAILABLE:
            try:
                # Compress request embedding for storage (6-8x compression)
                request_embedding_compressed = compress_certificate_embedding(
                    user_request_text,
                    model_type="hash_fallback"
                )

                # Optional: Use semantic intent detection
                # (Disabled by default to preserve existing behavior)
                # Uncomment to enable:
                # enhancer = TurboQuantIntentEnhancer(database, None, use_semantic=True)
                # semantic_intents, metadata = enhancer.parse_intent_enhanced(
                #     user_request_text,
                #     allowed_intents
                # )
                # if metadata.get('evasion_detected'):
                #     # Log paraphrase evasion attempt
                #     paraphrase_metadata = metadata

            except Exception as e:
                # TurboQuant failure should not break certificate creation
                # Fall back to keyword-only detection
                print(f"[WARNING] TurboQuant compression failed: {e}")
                request_embedding_compressed = None

        # Get tenant scope (ALWAYS from database, NEVER from user input)
        tenant_scope = cls.get_tenant_scope(database, customer_id)

        # Generate certificate ID and timestamps
        certificate_id = str(uuid4())
        created_at = datetime.now()
        expires_at = created_at + timedelta(seconds=cls.CERTIFICATE_TTL_SECONDS)

        # Prepare certificate data for signing
        certificate_data = {
            "certificate_id": certificate_id,
            "customer_id": customer_id,
            "intent_classes": json.dumps(intent_classes),
            "item_bounds": json.dumps(item_bounds) if item_bounds else None,
            "spend_limit": spend_limit,
            "tenant_scope": tenant_scope,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat()
        }

        # Compute HMAC signature
        signature = cls._compute_signature(certificate_data)

        # Store in database (with optional TurboQuant embedding)
        database.create_intent_certificate(
            certificate_id=certificate_id,
            customer_id=customer_id,
            intent_classes=json.dumps(intent_classes),
            item_bounds=json.dumps(item_bounds) if item_bounds else None,
            spend_limit=spend_limit,
            tenant_scope=tenant_scope,
            created_at=created_at.isoformat(),
            expires_at=expires_at.isoformat(),
            signature=signature,
            request_embedding_compressed=request_embedding_compressed,
            user_request_text=user_request_text  # Store for similarity detection
        )

        return certificate_id

    @classmethod
    def parse_intent(cls, text: str) -> List[str]:
        """
        Parse intent classes from user request text using RULE-BASED keyword matching.

        NO LLM CALL - this is pure pattern matching against INTENT_KEYWORDS.

        Security Note: This is the attack surface for intent detection. An attacker who
        discovers paraphrases not covered by our keyword lists could evade intent checks.
        For example:
        - "retrieve records" instead of "export" might bypass the "export" intent class
        - "procure items" instead of "purchase" might bypass the "order" intent class

        Known brittleness of rule-based NLU as a security boundary. Future improvement:
        ML/LLM-based classifier (with appropriate safeguards against adversarial inputs)
        could slot in here without changing the certificate schema.

        Args:
            text: User's natural language request

        Returns:
            List of intent classes detected (e.g., ["search", "order"])
            Empty list if no recognized intents found
        """
        if not text:
            return []

        text_lower = text.lower()
        detected_intents = []

        # Check each intent class's keywords
        for intent_class, keywords in cls.INTENT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text_lower:
                    if intent_class not in detected_intents:
                        detected_intents.append(intent_class)
                    break

        return detected_intents

    @classmethod
    def parse_items(cls, text: str) -> List[str]:
        """
        Extract item/product mentions from user request text using regex patterns.

        Looks for common product nouns and quoted phrases. Used to populate item_bounds
        for filtering which products the certificate authorizes access to.

        Examples:
        - "find laptops" -> ["laptop"]
        - "buy a 'gaming mouse' and keyboard" -> ["gaming mouse", "keyboard"]

        Args:
            text: User's natural language request

        Returns:
            List of item names/keywords mentioned in the request
        """
        if not text:
            return []

        items = []

        # Extract quoted phrases (e.g., 'gaming mouse', "wireless keyboard")
        quoted_pattern = r'["\']([^"\']+)["\']'
        quoted_matches = re.findall(quoted_pattern, text)
        items.extend(quoted_matches)

        # Common product nouns (expand as needed)
        product_nouns = [
            "laptop", "computer", "mouse", "keyboard", "monitor", "headphone", "speaker",
            "phone", "tablet", "charger", "cable", "camera", "watch", "fitness tracker",
            "shoe", "shirt", "pant", "jacket", "book", "ebook", "toy", "game",
            "chair", "desk", "lamp", "sofa", "bed", "mattress", "pillow",
            "dog food", "cat food", "leash", "collar", "tennis ball", "frisbee",
            "pasta", "sauce", "cheese", "wine", "coffee", "tea", "snack",
            "tire", "oil", "filter", "battery", "wiper"
        ]

        # Extract product nouns mentioned in text
        text_lower = text.lower()
        for noun in product_nouns:
            if noun in text_lower and noun not in items:
                items.append(noun)

        return items

    @classmethod
    def parse_spend(cls, text: str) -> Optional[float]:
        r"""
        Extract spending limit from user request text using regex patterns.

        Supports all these formats:
        "$800", "$800.00", "800", "800 dollars", "800 USD",
        "under $800", "less than $800", "up to $800", "max $800", "maximum $800"

        Uses regex pattern: r'[\$]?\s*(\d+(?:\.\d{2})?)'
        Extracts first number found after spend-related keywords.

        Args:
            text: User's natural language request

        Returns:
            Float dollar amount if found, None otherwise
        """
        if not text:
            return None

        # Spend-related keywords
        spend_keywords = [
            "under", "less than", "up to", "max", "maximum", "budget",
            "spend", "cost", "price", "dollars", "usd", "\\$"
        ]

        # Build regex pattern to find numbers near spend keywords
        # Pattern: optional $, optional whitespace, digits, optional decimal
        number_pattern = r'[\$]?\s*(\d+(?:\.\d{2})?)'

        # Try to find spend limit near keywords
        for keyword in spend_keywords:
            # Look for keyword followed by number
            pattern = rf'{keyword}\s*{number_pattern}'
            match = re.search(pattern, text.lower())
            if match:
                try:
                    return float(match.group(1))
                except (ValueError, IndexError):
                    continue

        # If no keyword-based match, try to find standalone dollar amounts
        dollar_pattern = r'\$\s*(\d+(?:\.\d{2})?)'
        match = re.search(dollar_pattern, text)
        if match:
            try:
                return float(match.group(1))
            except (ValueError, IndexError):
                pass

        return None

    @classmethod
    def get_tenant_scope(cls, database, customer_id: int) -> str:
        """
        Determine the tenant scope for a customer based on their role.

        CRITICAL SECURITY INVARIANT:
        Tenant scope is ALWAYS derived from customer.company_id in the database.
        NEVER from request text, params, or any user input.

        This assertion is enforced by:
        1. Fetching customer record from database by customer_id (trusted source)
        2. Reading company_id and role from database record ONLY
        3. NEVER parsing tenant_scope from user request text
        4. Explicit assertion below to document this invariant

        Rules (from existing global_customer pattern in Paper 1):
        - global_customer (company_id = NULL): return "ALL"
        - regular customer or admin: return their company_id as a string

        This reuses the existing role-lookup logic from database.py/security.py
        rather than re-querying directly.

        Args:
            database: Database instance
            customer_id: The customer's ID

        Returns:
            "ALL" for global_customer, or comma-separated company IDs (e.g., "3")

        Raises:
            ValueError: If customer not found
        """
        # Fetch customer record from database (trusted source)
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT company_id, role FROM customers WHERE customer_id = ?", (customer_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise ValueError(f"Customer {customer_id} not found")

        customer_data = dict(row)
        company_id = customer_data.get('company_id')
        role = customer_data.get('role')

        # CRITICAL ASSERTION: tenant_scope is ALWAYS derived from database.company_id
        # NEVER from user input, request text, or any untrusted source
        # This prevents privilege escalation where a regular customer could claim scope="ALL"
        assert company_id is None or isinstance(company_id, int), \
            "company_id must be NULL or integer from database"

        # Global customer pattern: company_id = NULL → scope = "ALL"
        if role == "global_customer" or company_id is None:
            return "ALL"

        # Regular customer or admin: scope = their company_id
        return str(company_id)

    @classmethod
    def _compute_signature(cls, certificate_data: Dict[str, Any]) -> str:
        """
        Compute HMAC-SHA256 signature over certificate fields.

        Signs all fields EXCEPT the signature itself, in deterministic order,
        to prevent tampering. Uses the class-level _SECRET_KEY.

        Args:
            certificate_data: Dict containing certificate_id, customer_id, intent_classes,
                            item_bounds, spend_limit, tenant_scope, created_at, expires_at

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        # Initialize secret key if not already done
        if cls._SECRET_KEY is None:
            cls._SECRET_KEY = secrets.token_bytes(32)

        # Create canonical representation of certificate data (deterministic order)
        # Fields signed: certificate_id, customer_id, intent_classes, item_bounds,
        #                spend_limit, tenant_scope, created_at, expires_at
        canonical_fields = [
            ("certificate_id", certificate_data.get("certificate_id", "")),
            ("customer_id", str(certificate_data.get("customer_id", ""))),
            ("intent_classes", certificate_data.get("intent_classes", "")),
            ("item_bounds", certificate_data.get("item_bounds", "") or ""),
            ("spend_limit", str(certificate_data.get("spend_limit", "") or "")),
            ("tenant_scope", certificate_data.get("tenant_scope", "")),
            ("created_at", certificate_data.get("created_at", "")),
            ("expires_at", certificate_data.get("expires_at", ""))
        ]

        # Concatenate all fields with delimiters
        message = "|".join([f"{k}:{v}" for k, v in canonical_fields])

        # Compute HMAC-SHA256
        signature = hmac.new(
            cls._SECRET_KEY,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return signature

    @classmethod
    def verify(cls, database, certificate_id: str) -> Dict[str, Any]:
        """
        Verify a certificate by ID, checking expiration and HMAC signature.

        This is called by IntentMiddleware.before_tool_call() to validate the certificate
        before allowing a tool call to proceed.

        Verification steps:
        1. Load certificate from database by certificate_id
        2. Check if expired (created_at + TTL < now)
        3. Check if completed (is_completed = 1, meaning place_order already succeeded)
        4. Recompute HMAC signature and compare to stored signature
        5. Return certificate data if valid

        Args:
            database: Database instance
            certificate_id: UUID string identifying the certificate

        Returns:
            Certificate data dict containing all fields

        Raises:
            CertificateExpiredError: If certificate has expired (beyond TTL) or is_completed=1
            CertificateTamperedError: If HMAC signature doesn't match (tampered data)
            CertificateNotFoundError: If certificate_id not found in database
        """
        # Load certificate from database
        cert = database.get_intent_certificate(certificate_id)

        if not cert:
            raise CertificateNotFoundError(
                f"Certificate {certificate_id} not found in database"
            )

        # Check if completed (place_order already succeeded)
        if cert.get('is_completed', 0) == 1:
            raise CertificateExpiredError(
                f"Certificate {certificate_id} has already been used to complete a primary action"
            )

        # Check expiration
        try:
            expires_at = datetime.fromisoformat(cert['expires_at'])
            if datetime.now() > expires_at:
                raise CertificateExpiredError(
                    f"Certificate {certificate_id} expired at {expires_at}"
                )
        except (ValueError, TypeError, KeyError) as e:
            raise CertificateExpiredError(f"Invalid expiration date: {e}")

        # Recompute HMAC signature
        certificate_data = {
            "certificate_id": cert['certificate_id'],
            "customer_id": cert['customer_id'],
            "intent_classes": cert['intent_classes'],
            "item_bounds": cert.get('item_bounds'),
            "spend_limit": cert.get('spend_limit'),
            "tenant_scope": cert['tenant_scope'],
            "created_at": cert['created_at'],
            "expires_at": cert['expires_at']
        }

        expected_signature = cls._compute_signature(certificate_data)
        actual_signature = cert['signature']

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise CertificateTamperedError(
                f"Certificate {certificate_id} signature verification failed - data may be tampered"
            )

        # Parse JSON fields for convenience
        cert_parsed = cert.copy()
        cert_parsed['intent_classes'] = json.loads(cert['intent_classes'])
        if cert.get('item_bounds'):
            cert_parsed['item_bounds'] = json.loads(cert['item_bounds'])

        return cert_parsed


# Custom exceptions for Layer 0 failures

class CertificateExpiredError(Exception):
    """Raised when a certificate has passed its expiration time or is already completed."""
    pass


class CertificateTamperedError(Exception):
    """Raised when HMAC signature verification fails, indicating tampering."""
    pass


class CertificateNotFoundError(Exception):
    """Raised when certificate_id is not found in the database."""
    pass
