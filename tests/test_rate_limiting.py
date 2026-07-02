import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_customer_rate_limit_allows_10_requests():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate to get user data
    success, user, msg = security.authenticate(db, "tz_cust1_key")
    assert success is True

    # First 10 calls should succeed
    for i in range(10):
        allowed, msg = security.check_rate_limit(
            db, user['api_key_hash'], user['role'], "search_products"
        )
        assert allowed is True, f"Request {i+1} should be allowed"


def test_customer_rate_limit_blocks_11th_request():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate
    success, user, msg = security.authenticate(db, "tz_cust2_key")
    assert success is True

    # Make 10 requests
    for i in range(10):
        security.check_rate_limit(db, user['api_key_hash'], user['role'], "search_products")

    # 11th request should fail
    allowed, msg = security.check_rate_limit(
        db, user['api_key_hash'], user['role'], "search_products"
    )

    assert allowed is False
    assert "Rate limit exceeded" in msg
    assert "10 calls/min" in msg


def test_admin_rate_limit_allows_5_requests():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate admin
    success, user, msg = security.authenticate(db, "tz_admin_secret_123")
    assert success is True

    # First 5 calls should succeed
    for i in range(5):
        allowed, msg = security.check_rate_limit(
            db, user['api_key_hash'], user['role'], "view_all_orders"
        )
        assert allowed is True, f"Admin request {i+1} should be allowed"


def test_admin_rate_limit_blocks_6th_request():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate admin
    success, user, msg = security.authenticate(db, "sp_admin_secret_456")
    assert success is True

    # Make 5 requests
    for i in range(5):
        security.check_rate_limit(db, user['api_key_hash'], user['role'], "view_all_orders")

    # 6th request should fail
    allowed, msg = security.check_rate_limit(
        db, user['api_key_hash'], user['role'], "view_all_orders"
    )

    assert allowed is False
    assert "Rate limit exceeded" in msg
    assert "5 calls/min" in msg


def test_different_users_have_independent_rate_limits():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # User 1
    success1, user1, msg1 = security.authenticate(db, "tz_cust1_key")
    assert success1 is True

    # User 2
    success2, user2, msg2 = security.authenticate(db, "sp_cust1_key")
    assert success2 is True

    # User 1 makes 10 requests
    for i in range(10):
        allowed, msg = security.check_rate_limit(
            db, user1['api_key_hash'], user1['role'], "search_products"
        )
        assert allowed is True

    # User 1's 11th request should fail
    allowed, msg = security.check_rate_limit(
        db, user1['api_key_hash'], user1['role'], "search_products"
    )
    assert allowed is False

    # User 2's first request should still work (independent counter)
    allowed, msg = security.check_rate_limit(
        db, user2['api_key_hash'], user2['role'], "search_products"
    )
    assert allowed is True, "User 2 should have independent rate limit counter"


def test_rate_limit_persists_in_database():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate
    success, user, msg = security.authenticate(db, "tz_cust2_key")
    assert success is True

    # Make 5 requests
    for i in range(5):
        security.check_rate_limit(db, user['api_key_hash'], user['role'], "search_products")

    # Check database has 5 entries
    count = db.get_rate_limit_count(user['api_key_hash'], window_seconds=60)
    assert count == 5, f"Expected 5 rate limit entries, got {count}"


def test_global_customer_has_customer_rate_limit():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear rate limit log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate global customer
    success, user, msg = security.authenticate(db, "global_cust_key")
    assert success is True
    assert user['role'] == "global_customer"

    # Should get customer rate limit (10 calls/min)
    for i in range(10):
        allowed, msg = security.check_rate_limit(
            db, user['api_key_hash'], user['role'], "search_products"
        )
        assert allowed is True, f"Global customer request {i+1} should be allowed"

    # 11th should fail
    allowed, msg = security.check_rate_limit(
        db, user['api_key_hash'], user['role'], "search_products"
    )
    assert allowed is False
