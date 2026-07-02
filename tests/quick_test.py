#!/usr/bin/env python3

import sqlite3
import os
from database import Database
from security import SecurityManager

# Use absolute path for database
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "ecommerce.db")

def test_database():
    """Test database is properly seeded"""
    print("\n🔍 Testing Database...")
    db = Database(DB_PATH)

    # Count records
    conn = db.get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM companies")
    companies = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM customers")
    customers = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM products")
    products = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM orders")
    orders = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM customers WHERE company_id IS NULL")
    global_customers = cursor.fetchone()[0]

    conn.close()

    print(f"  ✅ Companies: {companies} (expected: 8)")
    print(f"  ✅ Customers: {customers} (expected: 41)")
    print(f"  ✅ Global Customers: {global_customers} (expected: 1)")
    print(f"  ✅ Products: {products} (expected: 160)")
    print(f"  ✅ Orders: {orders} (expected: 80)")

    assert companies == 8, "Expected 8 companies"
    assert customers == 41, "Expected 41 customers"
    assert global_customers == 1, "Expected 1 global customer"
    assert products == 160, "Expected 160 products"
    assert orders == 80, "Expected 80 orders"

    print("  ✅ Database test PASSED!\n")


def test_authentication():
    """Test API key authentication with salt"""
    print("🔐 Testing Authentication...")
    db = Database(DB_PATH)
    security = SecurityManager()

    # Test valid global customer key
    success, user, msg = security.authenticate(db, "global_shopper_key_2024")
    assert success, f"Global customer auth failed: {msg}"
    assert user['email'] == "global@shopper.com", "Wrong user returned"
    assert user['role'] == "global_customer", "Wrong role"
    assert user['company_id'] is None, "Global customer should have NULL company_id"
    print("  ✅ Global customer authentication PASSED")

    # Test valid company customer key
    success, user, msg = security.authenticate(db, "techzone_sarah_key_2024")
    assert success, f"TechZone customer auth failed: {msg}"
    assert user['email'] == "sarah.j@email.com", "Wrong user returned"
    assert user['company_id'] == 1, "Wrong company ID"
    print("  ✅ Company customer authentication PASSED")

    # Test valid admin key
    success, user, msg = security.authenticate(db, "techzone_admin_key_2024")
    assert success, f"Admin auth failed: {msg}"
    assert user['role'] == "admin", "Wrong role"
    print("  ✅ Admin authentication PASSED")

    # Test invalid key
    success, user, msg = security.authenticate(db, "INVALID_KEY_12345")
    assert not success, "Invalid key should fail"
    assert "Invalid or expired" in msg, "Wrong error message"
    print("  ✅ Invalid key rejection PASSED")

    print("  ✅ Authentication test PASSED!\n")


def test_authorization():
    """Test role-based access control"""
    print("🛡️  Testing Authorization...")
    security = SecurityManager()

    # Test customer access to customer tools
    success, msg = security.authorize("search_products", "customer")
    assert success, "Customer should access search_products"
    print("  ✅ Customer can access customer tools")

    # Test customer blocked from admin tools
    success, msg = security.authorize("add_product", "customer")
    assert not success, "Customer should NOT access admin tools"
    assert "admin role required" in msg, "Wrong error message"
    print("  ✅ Customer blocked from admin tools")

    # Test global_customer access to customer tools
    success, msg = security.authorize("place_order", "global_customer")
    assert success, "Global customer should access customer tools"
    print("  ✅ Global customer can access customer tools")

    # Test global_customer blocked from admin tools
    success, msg = security.authorize("update_inventory", "global_customer")
    assert not success, "Global customer should NOT access admin tools"
    print("  ✅ Global customer blocked from admin tools")

    # Test admin access to all tools
    success, msg = security.authorize("search_products", "admin")
    assert success, "Admin should access customer tools"
    success, msg = security.authorize("add_product", "admin")
    assert success, "Admin should access admin tools"
    print("  ✅ Admin can access all tools")

    print("  ✅ Authorization test PASSED!\n")


def test_rate_limiting():
    """Test database-backed rate limiting"""
    print("⏱️  Testing Rate Limiting...")
    db = Database(DB_PATH)
    security = SecurityManager()

    # Clear old rate limits
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    # Authenticate user
    success, user, msg = security.authenticate(db, "techzone_sarah_key_2024")
    assert success, "Auth failed"

    # Test customer rate limit (10 calls/min)
    for i in range(10):
        allowed, msg = security.check_rate_limit(
            db, user['api_key_hash'], user['role'], "search_products"
        )
        assert allowed, f"Call {i+1} should be allowed"

    print("  ✅ First 10 calls allowed (customer limit)")

    # 11th call should fail
    allowed, msg = security.check_rate_limit(
        db, user['api_key_hash'], user['role'], "search_products"
    )
    assert not allowed, "11th call should be blocked"
    assert "Rate limit exceeded" in msg, "Wrong error message"
    print("  ✅ 11th call blocked (rate limit enforced)")

    # Test admin rate limit (5 calls/min)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rate_limit_log")
    conn.commit()
    conn.close()

    success, admin_user, msg = security.authenticate(db, "techzone_admin_key_2024")
    assert success, "Admin auth failed"

    for i in range(5):
        allowed, msg = security.check_rate_limit(
            db, admin_user['api_key_hash'], admin_user['role'], "view_all_orders"
        )
        assert allowed, f"Admin call {i+1} should be allowed"

    print("  ✅ First 5 calls allowed (admin limit)")

    # 6th call should fail
    allowed, msg = security.check_rate_limit(
        db, admin_user['api_key_hash'], admin_user['role'], "view_all_orders"
    )
    assert not allowed, "6th admin call should be blocked"
    print("  ✅ 6th admin call blocked (stricter admin limit)")

    print("  ✅ Rate limiting test PASSED!\n")


def test_security_alerts():
    """Test security alerts system"""
    print("🚨 Testing Security Alerts...")
    db = Database(DB_PATH)

    # Create test alert
    alert_id = db.create_security_alert(
        alert_type="test_alert",
        severity="MEDIUM",
        api_key_hash="test_hash",
        user_email="test@example.com",
        company_id=1,
        attempted_action="test_action",
        reason="Testing security alerts"
    )

    assert alert_id > 0, "Alert creation failed"
    print("  ✅ Security alert created")

    # Retrieve alerts
    alerts = db.get_security_alerts(company_id=1, limit=10)
    assert len(alerts) > 0, "No alerts retrieved"
    assert any(a['alert_type'] == 'test_alert' for a in alerts), "Test alert not found"
    print(f"  ✅ Retrieved {len(alerts)} security alerts")

    print("  ✅ Security alerts test PASSED!\n")


def test_global_customer_queries():
    """Test global customer can query all companies"""
    print("🌍 Testing Global Customer Queries...")
    db = Database(DB_PATH)

    # Search across all companies (no company filter)
    products = db.search_products("laptop", company_id=None, limit=50)

    # Check we got results from multiple companies
    company_ids = set(p['company_id'] for p in products)
    print(f"  ✅ Found products from {len(company_ids)} companies")
    assert len(company_ids) > 1, "Should find products from multiple companies"

    # Verify TechZone has laptops
    techzone_laptops = [p for p in products if p['company_id'] == 1]
    assert len(techzone_laptops) > 0, "TechZone should have laptops"
    print(f"  ✅ Found {len(techzone_laptops)} laptops in TechZone")

    print("  ✅ Global customer queries test PASSED!\n")


def test_input_validation():
    """Test enhanced input validation"""
    print("✔️  Testing Input Validation...")
    security = SecurityManager()

    # Test price validation
    valid, price, msg = security.validate_positive_number(100.50, "price")
    assert valid, "Valid price should pass"

    valid, price, msg = security.validate_positive_number(0.001, "price")
    assert not valid, "Price below $0.01 should fail"
    assert "$0.01" in msg, "Should mention minimum price"

    valid, price, msg = security.validate_positive_number(1000000, "price")
    assert not valid, "Price above $999,999.99 should fail"
    print("  ✅ Price validation working (min $0.01, max $999,999.99)")

    # Test quantity validation
    valid, qty, msg = security.validate_positive_integer(50, "quantity")
    assert valid, "Valid quantity should pass"

    valid, qty, msg = security.validate_positive_integer(500, "quantity")
    assert not valid, "Quantity above 100 should fail"
    assert "100" in msg, "Should mention max quantity"
    print("  ✅ Quantity validation working (max 100)")

    # Test search query validation
    valid, msg = security.validate_search_params("laptop", None, None)
    assert valid, "Valid search should pass"

    valid, msg = security.validate_search_params("a", None, None)
    assert not valid, "Too short search should fail"

    valid, msg = security.validate_search_params("laptop; DROP TABLE", None, None)
    assert not valid, "SQL injection attempt should fail"
    assert "invalid characters" in msg.lower() or "sql" in msg.lower(), "Should detect SQL keywords"
    print("  ✅ Search validation working (SQL injection blocked)")

    print("  ✅ Input validation test PASSED!\n")


def main():
    """Run all tests"""
    print("=" * 60)
    print("🧪 E-COMMERCE MCP - QUICK TEST SUITE")
    print("=" * 60)

    try:
        test_database()
        test_authentication()
        test_authorization()
        test_rate_limiting()
        test_security_alerts()
        test_global_customer_queries()
        test_input_validation()

        print("=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\n🎉 Your MCP server is working correctly!")
        print("\nNext steps:")
        print("1. Configure Claude Desktop (see TESTING_GUIDE.md)")
        print("2. Restart Claude Desktop")
        print("3. Try the example prompts in TESTING_GUIDE.md")
        print("\n📚 See TESTING_GUIDE.md for detailed testing instructions")

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
