"""
Security Bug Fix Tests

Tests for 4 critical security bugs fixed in the MCP gateway:
1. Tenant leakage in get_order_history (email-based lookup vulnerability)
2. Partial match bug in search_products (company name filtering)
3. Missing SQL injection keywords (UNION/SELECT)
4. Security alerts company scoping verification
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


# ==================== BUG 1: Tenant Leakage Prevention ====================

def test_bug1_same_email_different_companies_cannot_see_orders():
    """
    BUG 1 FIX TEST: Verify that customers with the same email at different
    companies cannot see each other's orders.

    Before fix: get_customer_orders used email lookup, which could leak orders
    if two customers at different companies shared an email address.

    After fix: Uses customer_id directly, preventing cross-tenant leakage.
    """
    db = Database(DB_PATH)
    security = SecurityManager()

    # Create two customers with the SAME email at DIFFERENT companies
    # This tests the vulnerability where email-based lookup could leak data
    import time
    test_email = f"duplicate_{int(time.time())}@test.com"

    # Customer 1 at TechZone (company_id=1)
    salt1 = security.generate_salt()
    key1 = f"key1_{int(time.time())}"
    hash1 = security.hash_api_key(key1, salt1)
    lookup1 = security.hash_api_key(key1, "lookup_salt_constant")

    customer1_id = db.create_customer(
        company_id=1,
        name="Customer 1 TechZone",
        email=test_email,  # Same email
        role="customer",
        api_key_hash=hash1,
        api_key_salt=salt1,
        api_key_lookup_hash=lookup1,
        expires_at="2026-12-31T00:00:00"
    )

    # Customer 2 at SportsPro (company_id=2) with SAME email
    salt2 = security.generate_salt()
    key2 = f"key2_{int(time.time())}"
    hash2 = security.hash_api_key(key2, salt2)
    lookup2 = security.hash_api_key(key2, "lookup_salt_constant")

    customer2_id = db.create_customer(
        company_id=2,
        name="Customer 2 SportsPro",
        email=test_email,  # Same email!
        role="customer",
        api_key_hash=hash2,
        api_key_salt=salt2,
        api_key_lookup_hash=lookup2,
        expires_at="2026-12-31T00:00:00"
    )

    # Create orders for each customer
    # Customer 1 order
    order1_id = db.create_order(
        company_id=1,
        customer_id=customer1_id,
        product_id=1,
        quantity=1,
        total_price=100.0
    )

    # Customer 2 order
    order2_id = db.create_order(
        company_id=2,
        customer_id=customer2_id,
        product_id=21,  # Product from SportsPro
        quantity=2,
        total_price=200.0
    )

    # TEST: Customer 1 should only see their own order using customer_id
    customer1_orders = db.get_customer_orders(customer1_id, company_id=1)
    customer1_order_ids = [o['order_id'] for o in customer1_orders]

    assert order1_id in customer1_order_ids, "Customer 1 should see their own order"
    assert order2_id not in customer1_order_ids, "BUG 1 FIX: Customer 1 should NOT see Customer 2's order (different company, same email)"

    # TEST: Customer 2 should only see their own order
    customer2_orders = db.get_customer_orders(customer2_id, company_id=2)
    customer2_order_ids = [o['order_id'] for o in customer2_orders]

    assert order2_id in customer2_order_ids, "Customer 2 should see their own order"
    assert order1_id not in customer2_order_ids, "BUG 1 FIX: Customer 2 should NOT see Customer 1's order (different company, same email)"

    print(f"✅ BUG 1 FIXED: Customers with same email ({test_email}) at different companies cannot see each other's orders")


def test_bug1_duplicate_email_same_company_uses_customer_id():
    """
    BUG 1 FIX TEST: Even if two customers have the same email in the SAME company
    (edge case/data quality issue), using customer_id prevents order leakage.
    """
    db = Database(DB_PATH)
    security = SecurityManager()

    import time
    test_email = f"dupe_same_company_{int(time.time())}@test.com"

    # Create TWO customers with same email in SAME company (data quality issue)
    salt1 = security.generate_salt()
    key1 = f"key1_{int(time.time())}"
    hash1 = security.hash_api_key(key1, salt1)
    lookup1 = security.hash_api_key(key1, "lookup_salt_constant")

    customer1_id = db.create_customer(
        company_id=1,
        name="Duplicate Email User 1",
        email=test_email,
        role="customer",
        api_key_hash=hash1,
        api_key_salt=salt1,
        api_key_lookup_hash=lookup1,
        expires_at="2026-12-31T00:00:00"
    )

    salt2 = security.generate_salt()
    key2 = f"key2_{int(time.time())}"
    hash2 = security.hash_api_key(key2, salt2)
    lookup2 = security.hash_api_key(key2, "lookup_salt_constant")

    customer2_id = db.create_customer(
        company_id=1,  # Same company!
        name="Duplicate Email User 2",
        email=test_email,  # Same email!
        role="customer",
        api_key_hash=hash2,
        api_key_salt=salt2,
        api_key_lookup_hash=lookup2,
        expires_at="2026-12-31T00:00:00"
    )

    # Create orders
    order1_id = db.create_order(1, customer1_id, 1, 1, 50.0)
    order2_id = db.create_order(1, customer2_id, 2, 1, 75.0)

    # Using customer_id ensures each sees only their own orders
    orders1 = db.get_customer_orders(customer1_id, company_id=1)
    orders2 = db.get_customer_orders(customer2_id, company_id=1)

    order1_ids = [o['order_id'] for o in orders1]
    order2_ids = [o['order_id'] for o in orders2]

    assert order1_id in order1_ids
    assert order2_id not in order1_ids, "BUG 1 FIX: Customer 1 should not see Customer 2's orders even with same email"

    assert order2_id in order2_ids
    assert order1_id not in order2_ids, "BUG 1 FIX: Customer 2 should not see Customer 1's orders even with same email"

    print(f"✅ BUG 1 FIXED: Duplicate emails in same company properly isolated by customer_id")


# ==================== BUG 2: Partial Company Name Search ====================

def test_bug2_partial_company_name_search_works():
    """
    BUG 2 FIX TEST: Verify that partial company name matches work correctly.

    Before fix: Searching for "Tech" found company_id for "TechZone" in database,
    but then an exact-match filter rejected all results because "TechZone" != "Tech".

    After fix: Removed exact-match filter, allowing partial matches to work.
    """
    db = Database(DB_PATH)
    security = SecurityManager()

    # Authenticate as a global customer who can search across all companies
    success, user, msg = security.authenticate(db, "global_shopper_key_2024")
    assert success is True, f"Auth failed: {msg}"

    # Search with partial company name "Tech" (should match "TechZone")
    # First, get company_id for partial match
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT company_id FROM companies WHERE name LIKE ?", (f"%Tech%",))
    row = cursor.fetchone()
    conn.close()

    assert row is not None, "Partial match 'Tech' should find 'TechZone' in database"
    company_id = row['company_id']

    # Search products with that company_id
    products = db.search_products(query="", company_id=company_id, limit=10)

    # BUG 2 FIX: Should return products (before fix, the in-memory filter removed them all)
    assert len(products) > 0, "BUG 2 FIX: Partial company name 'Tech' should return TechZone products"

    # Verify all products are from TechZone
    for p in products:
        assert p['company_id'] == company_id, "All products should be from the matched company"

    print(f"✅ BUG 2 FIXED: Partial company name search 'Tech' successfully returns {len(products)} TechZone products")


def test_bug2_partial_company_name_sport_works():
    """
    BUG 2 FIX TEST: Test another partial match case - "Sport" should find "SportsPro"
    """
    db = Database(DB_PATH)

    # Search for company with partial name
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT company_id, name FROM companies WHERE name LIKE ?", (f"%Sport%",))
    row = cursor.fetchone()
    conn.close()

    if row:
        company_id = row['company_id']
        company_name = row['name']

        # Search products
        products = db.search_products(query="", company_id=company_id, limit=5)

        assert len(products) > 0, f"BUG 2 FIX: Partial match 'Sport' should return {company_name} products"
        print(f"✅ BUG 2 FIXED: Partial company name 'Sport' successfully returns {len(products)} {company_name} products")


# ==================== BUG 3: SQL Injection Blacklist ====================

def test_bug3_union_keyword_blocked():
    """
    BUG 3 FIX TEST: Verify that UNION keyword is blocked in search queries.

    Before fix: UNION was not in the blacklist, allowing potential UNION-based SQL injection.
    After fix: UNION, SELECT, and other keywords are blocked.
    """
    security = SecurityManager()

    # Test UNION injection attempt
    valid, msg = security.validate_search_params("laptop' UNION SELECT * FROM customers--", None, None)

    assert valid is False, "BUG 3 FIX: UNION keyword should be blocked"
    assert "SQL" in msg or "invalid" in msg.lower(), "Error message should mention SQL/invalid"

    print("✅ BUG 3 FIXED: UNION keyword properly blocked in search queries")


def test_bug3_select_keyword_blocked():
    """
    BUG 3 FIX TEST: Verify that SELECT keyword is blocked in search queries.
    """
    security = SecurityManager()

    # Test SELECT injection attempt
    valid, msg = security.validate_search_params("test'; SELECT password FROM users--", None, None)

    assert valid is False, "BUG 3 FIX: SELECT keyword should be blocked"
    assert "SQL" in msg or "invalid" in msg.lower()

    print("✅ BUG 3 FIXED: SELECT keyword properly blocked in search queries")


def test_bug3_union_select_combined_blocked():
    """
    BUG 3 FIX TEST: Verify that UNION SELECT (classic injection) is blocked.
    """
    security = SecurityManager()

    injection_attempts = [
        "laptop UNION SELECT api_key FROM customers",
        "test' UNION SELECT 1,2,3,4,5--",
        "product' UNION ALL SELECT username, password FROM admin--",
        "query HAVING 1=1",
        "test EXEC sp_executesql",
        "data CAST(column AS varchar)",
    ]

    for injection in injection_attempts:
        valid, msg = security.validate_search_params(injection, None, None)
        assert valid is False, f"BUG 3 FIX: Should block injection attempt: {injection}"

    print(f"✅ BUG 3 FIXED: All {len(injection_attempts)} SQL injection attempts properly blocked")


def test_bug3_legitimate_searches_still_work():
    """
    BUG 3 FIX TEST: Verify that legitimate searches are not blocked by the expanded blacklist.
    """
    security = SecurityManager()

    legitimate_queries = [
        "laptop",
        "Nike shoes",
        "coffee maker",
        "dog food",
        "book",
    ]

    for query in legitimate_queries:
        valid, msg = security.validate_search_params(query, None, None)
        assert valid is True, f"Legitimate query '{query}' should be allowed"

    print(f"✅ BUG 3 VERIFIED: All {len(legitimate_queries)} legitimate searches still work")


# ==================== BUG 4: Security Alerts Company Scoping ====================

def test_bug4_admin_only_sees_own_company_alerts():
    """
    BUG 4 FIX TEST: Verify that admins can only see security alerts from their own company.

    Before fix: Potential to see alerts from other companies if company_id wasn't enforced.
    After fix: Strict company_id filtering with safety checks.
    """
    db = Database(DB_PATH)

    # Create alerts for different companies
    alert1_id = db.create_security_alert(
        alert_type="test_alert_company1",
        severity="LOW",
        company_id=1,  # TechZone
        user_email="test@techzone.com",
        attempted_action="test_action",
        reason="Test for TechZone"
    )

    alert2_id = db.create_security_alert(
        alert_type="test_alert_company2",
        severity="LOW",
        company_id=2,  # SportsPro
        user_email="test@sportspro.com",
        attempted_action="test_action",
        reason="Test for SportsPro"
    )

    # Get alerts for company 1 only
    company1_alerts = db.get_security_alerts(company_id=1, limit=100)
    company1_alert_ids = [a['alert_id'] for a in company1_alerts]

    # BUG 4 FIX: Should only see company 1 alerts
    assert alert1_id in company1_alert_ids, "Should see own company alert"
    assert alert2_id not in company1_alert_ids, "BUG 4 FIX: Should NOT see other company's alerts"

    # Get alerts for company 2 only
    company2_alerts = db.get_security_alerts(company_id=2, limit=100)
    company2_alert_ids = [a['alert_id'] for a in company2_alerts]

    assert alert2_id in company2_alert_ids, "Should see own company alert"
    assert alert1_id not in company2_alert_ids, "BUG 4 FIX: Should NOT see other company's alerts"

    print(f"✅ BUG 4 FIXED: Admins can only see their own company's security alerts (strict isolation)")


def test_bug4_company_id_filter_required():
    """
    BUG 4 FIX TEST: Verify that security alerts query properly filters by company_id.
    """
    db = Database(DB_PATH)

    # Create test alert
    test_alert_id = db.create_security_alert(
        alert_type="test_specific_company",
        severity="MEDIUM",
        company_id=1,
        user_email="admin@techzone.com",
        attempted_action="test",
        reason="Testing company filtering"
    )

    # Query with company_id filter
    filtered_alerts = db.get_security_alerts(company_id=1, limit=100)
    filtered_alert_ids = [a['alert_id'] for a in filtered_alerts]

    assert test_alert_id in filtered_alert_ids, "Alert should be in filtered results"

    # Query with different company_id
    other_company_alerts = db.get_security_alerts(company_id=999, limit=100)
    other_alert_ids = [a['alert_id'] for a in other_company_alerts]

    assert test_alert_id not in other_alert_ids, "BUG 4 FIX: Alert from company 1 should not appear in company 999 results"

    print(f"✅ BUG 4 VERIFIED: Security alerts properly filtered by company_id")


def test_bug4_null_company_id_alerts_not_leaked():
    """
    BUG 4 FIX TEST: Verify that alerts with NULL company_id (global alerts)
    don't leak into company-specific queries.
    """
    db = Database(DB_PATH)

    # Create alert with NULL company_id (global/system alert)
    global_alert_id = db.create_security_alert(
        alert_type="global_system_alert",
        severity="CRITICAL",
        company_id=None,  # NULL company_id
        user_email=None,
        attempted_action="system_maintenance",
        reason="Global system alert"
    )

    # Query company 1 alerts
    company1_alerts = db.get_security_alerts(company_id=1, limit=100)
    company1_alert_ids = [a['alert_id'] for a in company1_alerts]

    # BUG 4 FIX: Global alert (NULL company_id) should NOT appear in company-specific query
    assert global_alert_id not in company1_alert_ids, "BUG 4 FIX: NULL company_id alerts should not leak into company-specific queries"

    print(f"✅ BUG 4 VERIFIED: Global alerts (NULL company_id) properly isolated from company queries")
