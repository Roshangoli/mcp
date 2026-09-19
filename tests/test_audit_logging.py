import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager
from logger import AuditLogger
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_every_tool_call_creates_audit_log():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    # Count logs before
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    count_before = cursor.fetchone()[0]
    conn.close()

    # Make a tool call
    log_id = logger.log_tool_call(
        tool_name="search_products",
        company_id=1,
        user_email="alice@gmail.com",
        role="customer",
        input_params={"query": "laptop"},
        success=True,
        result="Found 3 products"
    )

    # Count logs after
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    count_after = cursor.fetchone()[0]
    conn.close()

    assert count_after == count_before + 1, "Tool call should create audit log entry"
    assert log_id > 0


def test_audit_log_contains_timestamp():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_tool_call(
        tool_name="test_tool",
        company_id=1,
        user_email="test@example.com",
        role="customer",
        input_params={},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    timestamp = row['timestamp']
    assert timestamp is not None
    assert isinstance(timestamp, str)
    # Should be parseable as datetime
    datetime.fromisoformat(timestamp.replace('Z', '+00:00'))


def test_audit_log_contains_user_email():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    test_email = "testuser@example.com"
    log_id = logger.log_tool_call(
        tool_name="test_tool",
        company_id=1,
        user_email=test_email,
        role="customer",
        input_params={},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_email FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['user_email'] == test_email


def test_audit_log_contains_role():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_tool_call(
        tool_name="test_tool",
        company_id=1,
        user_email="admin@example.com",
        role="admin",
        input_params={},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['role'] == "admin"


def test_audit_log_contains_tool_name():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    tool_name = "search_products"
    log_id = logger.log_tool_call(
        tool_name=tool_name,
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT tool_name FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['tool_name'] == tool_name


def test_api_keys_redacted_in_audit_logs():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    # Use a long API key
    long_api_key = "techzone_sarah_key_2024_very_long_secret"

    log_id = logger.log_tool_call(
        tool_name="test_tool",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"api_key": long_api_key},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT input_params FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    import json
    params = json.loads(row['input_params'])
    redacted_key = params['api_key']

    # Should show first4****last4
    assert "****" in redacted_key, "API key should be redacted"
    assert redacted_key.startswith(long_api_key[:4]), "Should show first 4 chars"
    assert redacted_key.endswith(long_api_key[-4:]), "Should show last 4 chars"
    assert long_api_key not in row['input_params'], "Full API key should not be in logs"


def test_short_api_key_fully_redacted():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    # Use a short API key
    short_api_key = "abc"

    log_id = logger.log_tool_call(
        tool_name="test_tool",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"api_key": short_api_key},
        success=True,
        result="test"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT input_params FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    import json
    params = json.loads(row['input_params'])
    redacted_key = params['api_key']

    # Should be fully masked
    assert "****" in redacted_key
    assert short_api_key not in row['input_params']


def test_failed_authentication_logged():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_authentication_failure(
        tool_name="search_products",
        error="Invalid API key provided"
    )

    assert log_id > 0

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['success'] == 0  # False
    assert "Invalid API key" in row['result'] or "authentication_failed" in row['input_params']


def test_authorization_failure_logged():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_authorization_failure(
        tool_name="add_product",
        user_email="customer@example.com",
        role="customer",
        error="Admin role required"
    )

    assert log_id > 0

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['success'] == 0
    assert row['user_email'] == "customer@example.com"
    assert row['role'] == "customer"


def test_rate_limit_violations_logged():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_rate_limit_exceeded(
        tool_name="search_products",
        user_email="spammer@example.com"
    )

    assert log_id > 0

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['success'] == 0
    assert "rate_limit_exceeded" in row['input_params'].lower() or "Rate limit" in row['result']


def test_validation_errors_logged():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_validation_error(
        tool_name="place_order",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"product_id": -1, "quantity": 0},
        error="Invalid product ID or quantity"
    )

    assert log_id > 0

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['success'] == 0
    assert "Invalid" in row['result']


def test_successful_tool_call_logged_with_result():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_tool_call(
        tool_name="get_product_details",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"product_id": 1},
        success=True,
        result="Product: Laptop, Price: $1200.00"
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['success'] == 1
    assert "Laptop" in row['result']


def test_audit_log_execution_time_tracked():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_tool_call(
        tool_name="search_products",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"query": "laptop"},
        success=True,
        result="Found 5 products",
        execution_time_ms=45.2
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT execution_time_ms FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['execution_time_ms'] == 45.2


def test_audit_log_result_count_tracked():
    db = Database(DB_PATH)
    logger = AuditLogger(db)

    log_id = logger.log_tool_call(
        tool_name="search_products",
        company_id=1,
        user_email="user@example.com",
        role="customer",
        input_params={"query": "laptop"},
        success=True,
        result="Found 5 products",
        result_count=5
    )

    # Retrieve the log
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT result_count FROM audit_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    assert row['result_count'] == 5
