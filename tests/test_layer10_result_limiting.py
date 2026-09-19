import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from security import SecurityManager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ecommerce.db")


def test_search_products_returns_maximum_50_results():
    db = Database(DB_PATH)

    # Create many products to ensure we have >50
    # First, count existing products
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM products")
    existing_count = cursor.fetchone()[0]
    conn.close()

    # Search with no filter to get all products
    results = db.search_products("", company_id=None, limit=1000)

    # Even though we requested 1000, should be capped at 50
    assert len(results) <= 50, f"Expected max 50 results, got {len(results)}"


def test_search_products_respects_explicit_50_limit():
    db = Database(DB_PATH)

    # Search with explicit limit=50
    results = db.search_products("", company_id=None, limit=50)

    assert len(results) <= 50, f"Expected max 50 results, got {len(results)}"


def test_search_products_with_higher_limit_still_capped():
    db = Database(DB_PATH)

    # Try to request 200 results
    results = db.search_products("", company_id=None, limit=200)

    # Should be capped at 50
    assert len(results) <= 50, f"Search should be capped at 50 results, got {len(results)}"


def test_admin_view_all_orders_maximum_100_results():
    db = Database(DB_PATH)

    # Get all orders with high limit
    orders = db.get_all_orders(company_id=1, limit=500)

    # Should be capped at 100
    assert len(orders) <= 100, f"Expected max 100 orders, got {len(orders)}"


def test_admin_view_all_orders_respects_100_limit():
    db = Database(DB_PATH)

    # Explicitly request 100
    orders = db.get_all_orders(company_id=1, limit=100)

    assert len(orders) <= 100, f"Expected max 100 orders, got {len(orders)}"


def test_global_customer_search_capped_at_50_across_all_companies():
    db = Database(DB_PATH)
    security = SecurityManager()

    # Authenticate as global customer
    success, user, msg = security.authenticate(db, "global_shopper_key_2024")
    assert success is True
    assert user['role'] == "global_customer"

    # Search across all companies with high limit
    results = db.search_products("", company_id=None, limit=1000)

    # Should be capped at 50 even across all companies
    assert len(results) <= 50, f"Global search should be capped at 50, got {len(results)}"


def test_customer_orders_history_respects_limit():
    db = Database(DB_PATH)

    # Get customer orders with high limit
    orders = db.get_customer_orders(company_id=1, customer_email="alice@gmail.com", limit=200)

    # Should respect system limits
    assert len(orders) <= 100, f"Customer order history should be limited, got {len(orders)}"


def test_search_with_category_filter_still_limited():
    db = Database(DB_PATH)

    # Search with category filter and high limit
    results = db.search_products("", company_id=None, category="Electronics", limit=500)

    # Should still be capped
    assert len(results) <= 50, f"Category search should be capped at 50, got {len(results)}"


def test_security_alerts_respects_limit():
    db = Database(DB_PATH)

    # Try to get many alerts
    alerts = db.get_security_alerts(company_id=1, limit=500)

    # Should be capped
    assert len(alerts) <= 100, f"Security alerts should be limited, got {len(alerts)}"


def test_result_limit_prevents_dos():
    db = Database(DB_PATH)

    # Try absurdly high limit
    results = db.search_products("", company_id=None, limit=999999)

    # Should be capped to prevent DoS
    assert len(results) <= 50, f"Absurd limit should be capped, got {len(results)}"
