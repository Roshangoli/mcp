import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import SecurityManager


def test_search_query_blocks_select_keyword():
    security = SecurityManager()

    valid, msg = security.validate_search_params("laptop; SELECT * FROM customers", None, None)

    assert valid is False
    assert "SQL" in msg or "invalid" in msg.lower()


def test_search_query_blocks_drop_keyword():
    security = SecurityManager()

    valid, msg = security.validate_search_params("laptop'; DROP TABLE products--", None, None)

    assert valid is False


def test_search_query_blocks_insert_keyword():
    security = SecurityManager()

    valid, msg = security.validate_search_params("'; INSERT INTO products VALUES", None, None)

    assert valid is False


def test_search_query_blocks_update_keyword():
    security = SecurityManager()

    valid, msg = security.validate_search_params("laptop'; UPDATE products SET price=0", None, None)

    assert valid is False


def test_search_query_blocks_delete_keyword():
    security = SecurityManager()

    valid, msg = security.validate_search_params("'; DELETE FROM products WHERE 1=1", None, None)

    assert valid is False


def test_search_query_sanitizes_semicolons():
    security = SecurityManager()

    valid, msg = security.validate_search_params("laptop; mouse; keyboard", None, None)

    assert valid is False
    assert "invalid characters" in msg.lower() or "semicolon" in msg.lower()


def test_price_validation_rejects_negative():
    security = SecurityManager()

    valid, price, msg = security.validate_positive_number(-10.50, "price")

    assert valid is False
    assert "0.01" in msg or "must be at least" in msg.lower()


def test_price_validation_rejects_above_maximum():
    security = SecurityManager()

    valid, price, msg = security.validate_positive_number(1000000, "price")

    assert valid is False
    assert "maximum" in msg.lower() or "999999" in msg or "999,999" in msg


def test_price_validation_accepts_valid_price():
    security = SecurityManager()

    valid, price, msg = security.validate_positive_number(99.99, "price")

    assert valid is True
    assert price == 99.99


def test_quantity_validation_rejects_zero():
    security = SecurityManager()

    valid, qty, msg = security.validate_positive_integer(0, "quantity")

    assert valid is False
    assert "must be at least 1" in msg or "at least" in msg.lower()


def test_quantity_validation_rejects_negative():
    security = SecurityManager()

    valid, qty, msg = security.validate_positive_integer(-5, "quantity")

    assert valid is False


def test_quantity_validation_rejects_above_maximum():
    security = SecurityManager()

    valid, qty, msg = security.validate_positive_integer(200, "quantity")

    assert valid is False
    assert "100" in msg


def test_quantity_validation_accepts_valid_quantity():
    security = SecurityManager()

    valid, qty, msg = security.validate_positive_integer(10, "quantity")

    assert valid is True
    assert qty == 10


def test_email_validation_accepts_valid_email():
    valid, email, msg = SecurityManager.validate_email("user@example.com")

    assert valid is True
    assert email == "user@example.com"


def test_email_validation_rejects_missing_at_sign():
    valid, email, msg = SecurityManager.validate_email("userexample.com")

    assert valid is False
    assert "email" in msg.lower() or "invalid" in msg.lower()


def test_email_validation_rejects_missing_domain():
    valid, email, msg = SecurityManager.validate_email("user@")

    assert valid is False


def test_email_validation_rejects_empty():
    valid, email, msg = SecurityManager.validate_email("")

    assert valid is False


def test_empty_search_query_handled_gracefully():
    security = SecurityManager()

    # Empty query might be allowed for "show all" or rejected for being too short
    valid, msg = security.validate_search_params("", None, None)

    # Either outcome is acceptable as long as it doesn't crash
    assert valid in [True, False]
    if not valid:
        assert "empty" in msg.lower() or "length" in msg.lower() or "characters" in msg.lower()


def test_very_short_search_query_rejected():
    security = SecurityManager()

    valid, msg = security.validate_search_params("a", None, None)

    assert valid is False
    assert "length" in msg.lower() or "characters" in msg.lower()


def test_valid_search_query_accepted():
    security = SecurityManager()

    valid, msg = security.validate_search_params("laptop", None, None)

    assert valid is True
    assert msg == ""
