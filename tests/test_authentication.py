import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_valid_customer_key_authenticates():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "tz_cust1_key")

    assert success is True
    assert user is not None
    assert user['email'] == "alice@gmail.com"
    assert user['role'] == "customer"
    assert msg == ""


def test_valid_admin_key_authenticates():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "tz_admin_secret_123")

    assert success is True
    assert user is not None
    assert user['email'] == "admin@techzone.com"
    assert user['role'] == "admin"


def test_valid_global_customer_key_authenticates():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "global_cust_key")

    assert success is True
    assert user is not None
    assert user['email'] == "global@world.com"
    assert user['role'] == "global_customer"
    assert user['company_id'] is None


def test_invalid_key_is_rejected():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "invalid_fake_key_12345")

    assert success is False
    assert user is None
    assert "Invalid or expired" in msg


def test_empty_key_is_rejected():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "")

    assert success is False
    assert user is None
    assert "Invalid or expired" in msg


def test_none_key_is_rejected():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, None)

    assert success is False
    assert user is None


def test_expired_key_is_rejected():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Create a test customer with expired key
    import time
    salt = security.generate_salt()
    expired_key = f"test_expired_key_{int(time.time())}"  # Unique key
    key_hash = security.hash_api_key(expired_key, salt)
    lookup_hash = security.hash_api_key(expired_key, "lookup_salt_constant")
    expired_date = (datetime.now() - timedelta(days=1)).isoformat()

    customer_id = db.create_customer(
        company_id=1,
        name="Expired Test User",
        email=f"expired{int(time.time())}@test.com",  # Unique email
        role="customer",
        api_key_hash=key_hash,
        api_key_salt=salt,
        api_key_lookup_hash=lookup_hash,
        expires_at=expired_date
    )

    success, user, msg = security.authenticate(db, expired_key)

    assert success is False
    assert user is None
    assert "expired" in msg.lower()


def test_customer_id_alias_is_set():
    db = Database(DB_PATH)
    security = SecurityManager()

    success, user, msg = security.authenticate(db, "tz_cust1_key")

    assert success is True
    assert 'id' in user
    assert user['id'] == user['customer_id']
