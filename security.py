import hashlib
import re
import secrets
from datetime import datetime
from typing import Optional, Tuple, Dict, Any


class SecurityManager:
    ROLE_CUSTOMER = "customer"
    ROLE_ADMIN = "admin"
    ROLE_GLOBAL_CUSTOMER = "global_customer"

    CUSTOMER_TOOLS = {
        "search_products",
        "get_product_details",
        "place_order",
        "track_order",
        "get_order_history",
        "view_orders"
    }

    ADMIN_TOOLS = {
        "add_product",
        "update_inventory",
        "view_all_orders",
        "update_order_status",
        "sales_summary",
        "rotate_api_key",
        "view_security_alerts"
    }

    VALID_COMPANIES = {
        "TechZone", "SportsPro", "HomeNest",
        "FashionHub", "BookWorld", "PetPalace",
        "GourmetMarket", "AutoGear"
    }

    VALID_ORDER_STATUSES = {"pending", "processing", "shipped", "delivered", "cancelled"}

    MAX_CALLS_PER_MINUTE_CUSTOMER = 10
    MAX_CALLS_PER_MINUTE_ADMIN = 5
    RATE_LIMIT_WINDOW = 60  # seconds

    MIN_PRICE = 0.01
    MAX_PRICE = 999999.99

    MIN_QUANTITY = 1
    MAX_QUANTITY = 100

    MIN_SEARCH_LENGTH = 2
    MAX_SEARCH_LENGTH = 100

    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self):
        # No longer needed - using database for rate limiting
        pass

    @staticmethod
    def generate_salt() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def hash_api_key(api_key: str, salt: str = "") -> str:
        combined = api_key + salt
        return hashlib.sha256(combined.encode()).hexdigest()

    def authenticate(self, db, api_key: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        if not api_key or not isinstance(api_key, str):
            return False, None, "Invalid or expired API key"

        # Fast lookup using a hash of the API key itself (without salt)
        # This allows O(1) database lookup while still storing the actual validation hash with a salt
        lookup_hash = self.hash_api_key(api_key, "lookup_salt_constant")
        user = db.get_customer_by_lookup_hash(lookup_hash)

        if user:
            # Secondary validation with per-user salt for defense-in-depth
            salt = user.get('api_key_salt', '')
            expected_hash = user['api_key_hash']
            actual_hash = self.hash_api_key(api_key, salt)

            if actual_hash == expected_hash:
                # Add 'id' alias for 'customer_id' for backward compatibility
                user['id'] = user['customer_id']
            else:
                user = None

        if not user:
            api_key_hash_temp = self.hash_api_key(api_key, "")
            failed_count = db.count_failed_auth_attempts(api_key_hash_temp, minutes=1)
            if failed_count >= 5:
                db.create_security_alert(
                    alert_type="repeated_auth_failures",
                    severity=self.SEVERITY_HIGH,
                    api_key_hash=api_key_hash_temp,
                    attempted_action="authentication",
                    reason=f"{failed_count + 1} failed auth attempts in 1 minute"
                )
            else:
                db.create_security_alert(
                    alert_type="authentication_failure",
                    severity=self.SEVERITY_MEDIUM,
                    api_key_hash=api_key_hash_temp,
                    attempted_action="authentication",
                    reason="Invalid API key provided"
                )

            return False, None, "Invalid or expired API key"

        # Check expiration
        if user.get('expires_at'):
            try:
                expires_at = datetime.fromisoformat(user['expires_at'])
                if datetime.now() > expires_at:
                    # Create security alert for expired key usage
                    db.create_security_alert(
                        alert_type="expired_key_usage",
                        severity=self.SEVERITY_HIGH,
                        api_key_hash=user['api_key_hash'],
                        user_email=user['email'],
                        company_id=user.get('company_id'),
                        attempted_action="authentication",
                        reason="Attempted use of expired API key"
                    )
                    return False, None, "API key expired. Please request a new key."

                # Check if expiring soon (within 7 days)
                days_until_expiry = (expires_at - datetime.now()).days
                if 0 < days_until_expiry <= 7:
                    db.create_security_alert(
                        alert_type="key_expiring_soon",
                        severity=self.SEVERITY_LOW,
                        api_key_hash=user['api_key_hash'],
                        user_email=user['email'],
                        company_id=user.get('company_id'),
                        attempted_action="authentication",
                        reason=f"API key expires in {days_until_expiry} days"
                    )
            except (ValueError, TypeError):
                pass  # Invalid date format, skip expiration check

        if user['role'] == self.ROLE_ADMIN:
            db.create_security_alert(
                alert_type="admin_login",
                severity=self.SEVERITY_LOW,
                api_key_hash=user['api_key_hash'],
                user_email=user['email'],
                company_id=user.get('company_id'),
                attempted_action="authentication",
                reason="Successful admin authentication"
            )

        return True, user, ""

    def authorize(self, tool_name: str, user_role: str) -> Tuple[bool, str]:
        if user_role == self.ROLE_ADMIN:
            return True, ""

        if user_role == self.ROLE_CUSTOMER or user_role == self.ROLE_GLOBAL_CUSTOMER:
            if tool_name in self.CUSTOMER_TOOLS:
                return True, ""
            else:
                return False, "Access denied: admin role required"

        return False, f"Unknown role: {user_role}"

    def check_rate_limit(self, db, api_key_hash: str, user_role: str, tool_name: str) -> Tuple[bool, str]:
        if user_role == self.ROLE_ADMIN:
            max_calls = self.MAX_CALLS_PER_MINUTE_ADMIN
        else:
            max_calls = self.MAX_CALLS_PER_MINUTE_CUSTOMER

        call_count = db.get_rate_limit_count(api_key_hash, self.RATE_LIMIT_WINDOW)

        if call_count >= max_calls:
            return False, f"Rate limit exceeded ({max_calls} calls/min), wait 60 seconds"

        db.log_rate_limit_call(api_key_hash, tool_name)

        try:
            db.cleanup_old_rate_limits(hours_old=24)
        except:
            pass  # Don't fail if cleanup fails

        return True, ""

    def validate_positive_number(self, value: Any, field_name: str) -> Tuple[bool, Optional[float], str]:
        try:
            num = float(value)
            if num < self.MIN_PRICE:
                return False, None, f"{field_name} must be at least ${self.MIN_PRICE}"
            if num > self.MAX_PRICE:
                return False, None, f"{field_name} cannot exceed ${self.MAX_PRICE}"
            return True, num, ""
        except (ValueError, TypeError):
            return False, None, f"{field_name} must be a valid number"

    def validate_positive_integer(self, value: Any, field_name: str) -> Tuple[bool, Optional[int], str]:
        try:
            num = int(value)
            if num < self.MIN_QUANTITY:
                return False, None, f"{field_name} must be at least {self.MIN_QUANTITY}"
            if num > self.MAX_QUANTITY:
                return False, None, f"{field_name} cannot exceed {self.MAX_QUANTITY} (bulk order limit)"
            return True, num, ""
        except (ValueError, TypeError):
            return False, None, f"{field_name} must be a valid integer"

    @staticmethod
    def validate_non_negative_integer(value: Any, field_name: str) -> Tuple[bool, Optional[int], str]:
        try:
            num = int(value)
            if num < 0:
                return False, None, f"{field_name} must be non-negative"
            return True, num, ""
        except (ValueError, TypeError):
            return False, None, f"{field_name} must be a valid integer"

    def validate_order_status(self, status: str) -> Tuple[bool, str, str]:
        if not isinstance(status, str):
            return False, "", "Status must be a string"

        status_clean = status.strip().lower()
        if status_clean not in self.VALID_ORDER_STATUSES:
            valid_statuses = ", ".join(sorted(self.VALID_ORDER_STATUSES))
            return False, "", f"Invalid status. Must be one of: {valid_statuses}"

        return True, status_clean, ""

    @staticmethod
    def sanitize_string(text: str, max_length: int = 500) -> str:
        if not isinstance(text, str):
            return ""

        # Strip whitespace
        text = text.strip()

        # Limit length
        if len(text) > max_length:
            text = text[:max_length]

        return text

    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str, str]:
        if not isinstance(email, str):
            return False, "", "Email must be a string"

        email = email.strip().lower()

        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "", "Invalid email format"

        return True, email, ""

    def validate_company_name(self, name: str) -> Tuple[bool, str]:
        if name is None:
            return True, ""

        if not isinstance(name, str):
            return False, "Company name must be a string"

        name_stripped = name.strip()

        if len(name_stripped) == 0:
            return False, "Company name cannot be empty"

        # Check against whitelist
        if name_stripped not in self.VALID_COMPANIES:
            valid_names = ", ".join(sorted(self.VALID_COMPANIES))
            return False, f"Invalid company name. Valid companies: {valid_names}"

        return True, ""

    def validate_search_params(self, query: str, max_price: Optional[float] = None,
                               category: Optional[str] = None) -> Tuple[bool, str]:
        if not isinstance(query, str):
            return False, "Search query must be a string"

        query_stripped = query.strip()

        if len(query_stripped) == 0:
            return False, "Search query cannot be empty"

        # Check minimum length
        if len(query_stripped) < self.MIN_SEARCH_LENGTH:
            return False, f"Search query must be at least {self.MIN_SEARCH_LENGTH} characters"

        # Check maximum length
        if len(query_stripped) > self.MAX_SEARCH_LENGTH:
            return False, f"Search query cannot exceed {self.MAX_SEARCH_LENGTH} characters"

        # Block dangerous SQL characters
        dangerous_patterns = [';', '--', '/*', '*/', 'DROP', 'DELETE', 'UPDATE', 'INSERT']
        for pattern in dangerous_patterns:
            if pattern in query.upper():
                return False, "Search query contains invalid characters or SQL keywords"

        # Max price must be positive if provided
        if max_price is not None:
            valid, _, msg = self.validate_positive_number(max_price, "max_price")
            if not valid:
                return False, msg

        # Category is optional string
        if category is not None and not isinstance(category, str):
            return False, "Category must be a string"

        return True, ""

    def validate_product_data(self, name: str, category: str, price: float,
                             stock: int, description: str) -> Tuple[bool, str]:
        if not isinstance(name, str) or len(name.strip()) == 0:
            return False, "Product name cannot be empty"

        # Category validation
        if not isinstance(category, str) or len(category.strip()) == 0:
            return False, "Category cannot be empty"

        # Price validation
        valid, _, msg = self.validate_positive_number(price, "price")
        if not valid:
            return False, msg

        # Stock validation
        valid, _, msg = self.validate_non_negative_integer(stock, "stock")
        if not valid:
            return False, msg

        # Description validation (can be empty)
        if not isinstance(description, str):
            return False, "Description must be a string"

        return True, ""


# Global security manager instance
security_manager = SecurityManager()
